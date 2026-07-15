#!/usr/bin/env python3
"""Validate the bundled Hiker dataset provenance without third-party dependencies."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

SCHEMA_VERSION = "1.0.0"
M1_DATASET_VERSION = "1.0.0-rc.1"
ENTRY_COUNT = 100
M0_STATUS = "candidate_unapproved"
CANDIDATE_STATUS = "release_candidate_public_official_source"
LEGACY_CANDIDATE_STATUS = "release_candidate_legacy_mapping"
RELEASE_STATUS = "approved"
NOT_HUMAN_REVIEWED = "not_human_reviewed"
OFFICIAL_SOURCE_URL = "https://map.forest.go.kr/forest/?systype=appdata"
OFFICIAL_SERVICE_URL = "https://map.forest.go.kr/gis1/iserver/services/data-fdms/rest/data"
OFFICIAL_ENDPOINT = (
    "https://map.forest.go.kr/gis1/iserver/services/"
    "data-fdms/rest/data/featureResults.json?returnContent=true"
)
OFFICIAL_DATASET = "FDMS_BASE:TB_FGDI_FS_F100"
OFFICIAL_SOURCE_CRS = "EPSG:5179"
OFFICIAL_RETRIEVED_AT = "2026-07-14T00:03:32.659Z"
OFFICIAL_SOURCE_SHA256 = "c82eab718f45afc58bbe45d7f6a4904187fb7f0d0cd6aadd0a287ae78d13128d"
OFFICIAL_QUERY = "1=1"
RAW_SNAPSHOT_PATH = "Evidence/dataset/official-100-mountains-v1.raw.json"
NORMALIZED_SNAPSHOT_PATH = "Evidence/dataset/official-100-mountains-v1.normalized.json"
COORDINATE_BINDING_ABSOLUTE_TOLERANCE_DEGREES = 1e-7
CATALOG_RESOURCE = "official-100-mountains-v1"
CATALOG_SHA256 = "1032070f3d7ea12ae68be5859bb1eef353ab815da763f23f8940527b39783cae"
LEGACY_RESOURCE = "legacy-mountain-metadata-v1"
LEGACY_SHA256 = "04028d8e4895eff00cdcd96267460eebb0ccaed3450c643ef06b30e1c87ffc73"

M0_ROOT_FIELDS = frozenset(
    {"schemaVersion", "datasetVersion", "status", "source", "content", "review", "entries"}
)
M1_ROOT_FIELDS = frozenset(
    {
        "schemaVersion",
        "datasetVersion",
        "status",
        "source",
        "content",
        "legacy",
        "review",
        "entryCount",
    }
)
M0_SOURCE_FIELDS = frozenset({"status", "url", "reference", "retrievedAt", "sha256"})
M0_CONTENT_FIELDS = frozenset({"status", "sha256"})
SOURCE_FIELDS = frozenset(
    {
        "status",
        "url",
        "service",
        "dataset",
        "crs",
        "retrievedAt",
        "sha256",
        "rawResource",
        "normalizedSnapshotPath",
    }
)
CONTENT_FIELDS = frozenset({"status", "resource", "coordinateReferenceSystem", "sha256"})
LEGACY_FIELDS = frozenset({"status", "resource", "sha256"})
REVIEW_FIELDS = frozenset({"status", "reviewers", "reviewedAt"})
REVIEWER_FIELDS = frozenset({"id", "role", "reviewedAt", "decision"})
CATALOG_FIELDS = frozenset(
    {"schemaVersion", "datasetVersion", "status", "coordinateReferenceSystem", "entries"}
)
CATALOG_ENTRY_FIELDS = frozenset(
    {"id", "sourceReference", "name", "administrativeCode", "longitude", "latitude"}
)
LEGACY_DOCUMENT_FIELDS = frozenset({"schemaVersion", "datasetVersion", "status", "entries"})
LEGACY_ENTRY_FIELDS = frozenset({"legacyID", "currentID"})

NORMALIZED_SNAPSHOT_FIELDS = frozenset(
    {"schemaVersion", "source", "recordCount", "recordsSHA256", "records"}
)
NORMALIZED_SNAPSHOT_SOURCE_FIELDS = frozenset(
    {
        "publisher",
        "page",
        "endpoint",
        "table",
        "query",
        "sourceCoordinateReferenceSystem",
        "targetCoordinateReferenceSystem",
        "retrievedAt",
        "rawSHA256",
    }
)
NORMALIZED_RECORD_FIELDS = frozenset(
    {
        "officialMountainID",
        "name",
        "elevationMeters",
        "administrativeCode",
        "administrativeName",
        "representativePoint",
    }
)
NORMALIZED_POINT_FIELDS = frozenset({"latitude", "longitude", "epsg"})
SEMVER_PATTERN = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
OPAQUE_ID_PATTERN = re.compile(r"^hkr_mtn_[0-9a-f]{32}$")
REVIEWER_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$")
ADMINISTRATIVE_CODE_PATTERN = re.compile(r"^[0-9]{8}$")
UTC_TIMESTAMP_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$"
)

BROAD_REGIONS = {
    "11": "Seoul",
    "26": "Busan",
    "27": "Daegu",
    "28": "Incheon",
    "29": "Gwangju",
    "30": "Daejeon",
    "31": "Ulsan",
    "36": "Sejong",
    "41": "Gyeonggi",
    "43": "Chungcheongbuk-do",
    "44": "Chungcheongnam-do",
    "46": "Jeollanam-do",
    "47": "Gyeongsangbuk-do",
    "48": "Gyeongsangnam-do",
    "50": "Jeju",
    "51": "Gangwon",
    "52": "Jeonbuk",
}


class DuplicateKeyError(ValueError):
    """Raised when a JSON object repeats a field name."""


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"duplicate object field: {key}")
        result[key] = value
    return result

def reject_nonstandard_constant(value: str) -> None:
    raise ValueError(f"nonstandard JSON constant is not allowed: {value}")


def parse_utc_timestamp(value: Any) -> datetime | None:
    if type(value) is not str or UTC_TIMESTAMP_PATTERN.fullmatch(value) is None:
        return None
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return None


def is_prerelease_semver(value: str) -> bool:
    return "-" in value.partition("+")[0]



def add_error(errors: list[str], path: str, message: str) -> None:
    errors.append(f"{path}: {message}")


def require_exact_fields(
    value: Any, path: str, fields: frozenset[str], errors: list[str]
) -> dict[str, Any] | None:
    if type(value) is not dict:
        add_error(errors, path, "must be an object")
        return None

    actual_fields = frozenset(value)
    missing = sorted(fields - actual_fields)
    unexpected = sorted(actual_fields - fields)
    if missing:
        add_error(errors, path, f"is missing required fields: {', '.join(missing)}")
    if unexpected:
        add_error(errors, path, f"has unsupported fields: {', '.join(unexpected)}")
    return value


def valid_sha256(value: Any) -> bool:
    return isinstance(value, str) and SHA256_PATTERN.fullmatch(value) is not None


def valid_utc_timestamp(value: Any) -> bool:
    return parse_utc_timestamp(value) is not None


def valid_https_url(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    parsed = urlparse(value)
    return parsed.scheme == "https" and bool(parsed.netloc)


def valid_number(value: Any) -> bool:
    return type(value) is int or (type(value) is float and math.isfinite(value))

def representative_coordinate_matches(catalog_value: Any, source_value: Any) -> bool:
    return (
        valid_number(catalog_value)
        and valid_number(source_value)
        and abs(catalog_value - source_value)
        <= COORDINATE_BINDING_ABSOLUTE_TOLERANCE_DEGREES
    )



def opaque_id_for(source_reference: str) -> str:
    seed = f"kfs:{OFFICIAL_DATASET}:{source_reference}".encode("utf-8")
    return f"hkr_mtn_{hashlib.sha256(seed).hexdigest()[:32]}"


def broad_region_for(administrative_code: Any) -> str | None:
    if not isinstance(administrative_code, str):
        return None
    if ADMINISTRATIVE_CODE_PATTERN.fullmatch(administrative_code) is None:
        return None
    return BROAD_REGIONS.get(administrative_code[:2])


def validate_m0_skeleton(manifest: Any, errors: list[str]) -> None:
    root = require_exact_fields(manifest, "manifest", M0_ROOT_FIELDS, errors)
    if root is None:
        return

    if root.get("schemaVersion") != SCHEMA_VERSION:
        add_error(errors, "schemaVersion", f"must be '{SCHEMA_VERSION}'")
    dataset_version = root.get("datasetVersion")
    if not isinstance(dataset_version, str) or SEMVER_PATTERN.fullmatch(dataset_version) is None:
        add_error(errors, "datasetVersion", "must be a semantic version")
    if root.get("status") != M0_STATUS:
        add_error(errors, "status", f"must be '{M0_STATUS}' in skeleton mode")

    source = require_exact_fields(root.get("source"), "source", M0_SOURCE_FIELDS, errors)
    if source is not None:
        if source.get("status") != M0_STATUS:
            add_error(errors, "source.status", f"must be '{M0_STATUS}'")
        for field in ("url", "reference", "retrievedAt", "sha256"):
            if source.get(field) is not None:
                add_error(errors, f"source.{field}", "must be null in an M0 skeleton")

    content = require_exact_fields(root.get("content"), "content", M0_CONTENT_FIELDS, errors)
    if content is not None:
        if content.get("status") != M0_STATUS:
            add_error(errors, "content.status", f"must be '{M0_STATUS}'")
        if content.get("sha256") is not None:
            add_error(errors, "content.sha256", "must be null in an M0 skeleton")

    review = require_exact_fields(root.get("review"), "review", REVIEW_FIELDS, errors)
    if review is not None:
        if review.get("status") != M0_STATUS:
            add_error(errors, "review.status", f"must be '{M0_STATUS}'")
        if review.get("reviewers") != []:
            add_error(errors, "review.reviewers", "must be an empty array in an M0 skeleton")
        if review.get("reviewedAt") is not None:
            add_error(errors, "review.reviewedAt", "must be null in an M0 skeleton")

    if root.get("entries") != []:
        add_error(errors, "entries", "must be an empty array in an M0 skeleton")


def validate_source(
    source_value: Any, mode: str, errors: list[str]
) -> dict[str, Any] | None:
    source = require_exact_fields(source_value, "source", SOURCE_FIELDS, errors)
    if source is None:
        return None

    expected_status = CANDIDATE_STATUS if mode == "candidate" else RELEASE_STATUS
    if source.get("status") != expected_status:
        add_error(errors, "source.status", f"must be '{expected_status}'")
    for field, expected in (
        ("url", OFFICIAL_SOURCE_URL),
        ("service", OFFICIAL_SERVICE_URL),
        ("dataset", OFFICIAL_DATASET),
        ("crs", OFFICIAL_SOURCE_CRS),
        ("rawResource", RAW_SNAPSHOT_PATH),
        ("normalizedSnapshotPath", NORMALIZED_SNAPSHOT_PATH),
    ):
        if source.get(field) != expected:
            add_error(errors, f"source.{field}", f"must be '{expected}'")
    if not valid_https_url(source.get("url")):
        add_error(errors, "source.url", "must be a non-empty HTTPS URL")
    if not valid_https_url(source.get("service")):
        add_error(errors, "source.service", "must be a non-empty HTTPS URL")
    if not valid_utc_timestamp(source.get("retrievedAt")):
        add_error(errors, "source.retrievedAt", "must be an ISO 8601 UTC timestamp")
    if not valid_sha256(source.get("sha256")):
        add_error(errors, "source.sha256", "must be a lowercase 64-character SHA-256")

    if mode == "candidate":
        if source.get("retrievedAt") != OFFICIAL_RETRIEVED_AT:
            add_error(errors, "source.retrievedAt", "does not match the M1 source snapshot")
        if source.get("sha256") != OFFICIAL_SOURCE_SHA256:
            add_error(errors, "source.sha256", "does not match the M1 source snapshot")
    return source


def validate_content(
    content_value: Any, mode: str, errors: list[str]
) -> dict[str, Any] | None:
    content = require_exact_fields(content_value, "content", CONTENT_FIELDS, errors)
    if content is None:
        return None

    expected_status = CANDIDATE_STATUS if mode == "candidate" else RELEASE_STATUS
    if content.get("status") != expected_status:
        add_error(errors, "content.status", f"must be '{expected_status}'")
    if content.get("resource") != CATALOG_RESOURCE:
        add_error(errors, "content.resource", f"must be '{CATALOG_RESOURCE}'")
    if content.get("coordinateReferenceSystem") != "WGS84":
        add_error(errors, "content.coordinateReferenceSystem", "must be 'WGS84'")
    if not valid_sha256(content.get("sha256")):
        add_error(errors, "content.sha256", "must be a lowercase 64-character SHA-256")
    if mode == "candidate" and content.get("sha256") != CATALOG_SHA256:
        add_error(errors, "content.sha256", "does not match the M1 catalog checksum")
    return content


def validate_legacy_provenance(
    legacy_value: Any, mode: str, errors: list[str]
) -> dict[str, Any] | None:
    legacy = require_exact_fields(legacy_value, "legacy", LEGACY_FIELDS, errors)
    if legacy is None:
        return None

    expected_status = LEGACY_CANDIDATE_STATUS if mode == "candidate" else RELEASE_STATUS
    if legacy.get("status") != expected_status:
        add_error(errors, "legacy.status", f"must be '{expected_status}'")
    if legacy.get("resource") != LEGACY_RESOURCE:
        add_error(errors, "legacy.resource", f"must be '{LEGACY_RESOURCE}'")
    if not valid_sha256(legacy.get("sha256")):
        add_error(errors, "legacy.sha256", "must be a lowercase 64-character SHA-256")
    if mode == "candidate" and legacy.get("sha256") != LEGACY_SHA256:
        add_error(errors, "legacy.sha256", "does not match the M1 legacy checksum")
    return legacy


def validate_release_review(
    value: Any, source_retrieved_at: Any, errors: list[str]
) -> None:
    review = require_exact_fields(value, "review", REVIEW_FIELDS, errors)
    if review is None:
        return

    source_retrieved = parse_utc_timestamp(source_retrieved_at)
    review_completed = parse_utc_timestamp(review.get("reviewedAt"))
    if review.get("status") != RELEASE_STATUS:
        add_error(errors, "review.status", f"must be '{RELEASE_STATUS}' in release mode")
    reviewers = review.get("reviewers")
    if type(reviewers) is not list:
        add_error(errors, "review.reviewers", "must be an array")
    else:
        reviewer_ids: set[str] = set()
        for index, reviewer in enumerate(reviewers):
            path = f"review.reviewers[{index}]"
            reviewer_object = require_exact_fields(reviewer, path, REVIEWER_FIELDS, errors)
            if reviewer_object is None:
                continue
            reviewer_id = reviewer_object.get("id")
            if (
                not isinstance(reviewer_id, str)
                or REVIEWER_ID_PATTERN.fullmatch(reviewer_id) is None
            ):
                add_error(errors, f"{path}.id", "must be a stable reviewer identifier")
            elif reviewer_id in reviewer_ids:
                add_error(errors, f"{path}.id", "must not duplicate another reviewer")
            else:
                reviewer_ids.add(reviewer_id)
            if reviewer_object.get("role") != "Data Steward":
                add_error(errors, f"{path}.role", "must be 'Data Steward'")
            if reviewer_object.get("decision") != "approved":
                add_error(errors, f"{path}.decision", "must be 'approved'")

            reviewer_approved = parse_utc_timestamp(reviewer_object.get("reviewedAt"))
            if reviewer_approved is None:
                add_error(errors, f"{path}.reviewedAt", "must be an ISO 8601 UTC timestamp")
            else:
                if (
                    source_retrieved is not None
                    and reviewer_approved < source_retrieved
                ):
                    add_error(
                        errors,
                        f"{path}.reviewedAt",
                        "must not precede source.retrievedAt",
                    )
                if (
                    review_completed is not None
                    and reviewer_approved > review_completed
                ):
                    add_error(
                        errors,
                        f"{path}.reviewedAt",
                        "must not follow review.reviewedAt",
                    )
        if len(reviewer_ids) < 2:
            add_error(errors, "review.reviewers", "must contain two independent Data Stewards")
    if review_completed is None:
        add_error(errors, "review.reviewedAt", "must be an ISO 8601 UTC timestamp")


def validate_candidate_review(value: Any, errors: list[str]) -> None:
    review = require_exact_fields(value, "review", REVIEW_FIELDS, errors)
    if review is None:
        return

    if review.get("status") != NOT_HUMAN_REVIEWED:
        add_error(errors, "review.status", f"must be '{NOT_HUMAN_REVIEWED}' in candidate mode")
    if review.get("reviewers") != []:
        add_error(errors, "review.reviewers", "must be an empty array before human review")
    if review.get("reviewedAt") is not None:
        add_error(errors, "review.reviewedAt", "must be null before human review")


def read_json_document(
    path: Path, label: str, errors: list[str]
) -> tuple[Any, bytes] | None:
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        add_error(errors, label, f"resource not found: {path}")
        return None
    except OSError as error:
        add_error(errors, label, f"could not read {path}: {error}")
        return None

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        add_error(errors, label, f"invalid UTF-8 JSON: {error}")
        return None
    try:
        return (
            json.loads(
                text,
                object_pairs_hook=reject_duplicate_keys,
                parse_constant=reject_nonstandard_constant,
            ),
            data,
        )
    except DuplicateKeyError as error:
        add_error(errors, label, f"invalid JSON: {error}")
    except json.JSONDecodeError as error:
        add_error(errors, label, f"invalid JSON: {error}")
    except ValueError as error:
        add_error(errors, label, f"invalid JSON: {error}")
    return None
def repository_root() -> Path:
    return Path(__file__).resolve().parents[2]


def resolve_repository_resource(
    source: dict[str, Any], field: str, errors: list[str]
) -> Path | None:
    value = source.get(field)
    if not isinstance(value, str) or not value:
        add_error(errors, f"source.{field}", "must be a non-empty repository-relative path")
        return None

    declared_path = Path(value)
    if declared_path.is_absolute():
        add_error(errors, f"source.{field}", "must be a repository-relative path")
        return None

    root = repository_root()
    resolved_path = (root / declared_path).resolve()
    try:
        resolved_path.relative_to(root)
    except ValueError:
        add_error(errors, f"source.{field}", "must resolve within the repository")
        return None
    return resolved_path


def read_resource_bytes(path: Path, label: str, errors: list[str]) -> bytes | None:
    try:
        return path.read_bytes()
    except FileNotFoundError:
        add_error(errors, label, f"resource not found: {path}")
    except OSError as error:
        add_error(errors, label, f"could not read {path}: {error}")
    return None
def recompute_normalized_snapshot(
    raw_resource: bytes, retrieved_at: str, errors: list[str]
) -> dict[str, Any] | None:
    fetcher_path = Path(__file__).with_name("fetch-official-100.py")
    try:
        specification = importlib.util.spec_from_file_location(
            "_hiker_dataset_fetch_official_100", fetcher_path
        )
        if specification is None or specification.loader is None:
            raise ImportError(f"could not load {fetcher_path}")
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)
        normalize = getattr(module, "normalize", None)
        if not callable(normalize):
            raise AttributeError("shared fetch normalizer is missing")
        normalized_snapshot = normalize(raw_resource, retrieved_at)
    except Exception as error:
        add_error(
            errors,
            "normalizedSnapshot",
            f"could not re-run the shared fetch normalizer: {error}",
        )
        return None

    if type(normalized_snapshot) is not dict:
        add_error(
            errors,
            "normalizedSnapshot",
            "shared fetch normalizer did not return an object",
        )
        return None
    return normalized_snapshot




def validate_normalized_snapshot(
    snapshot_value: Any, manifest_source: dict[str, Any], errors: list[str]
) -> list[dict[str, Any]] | None:
    snapshot = require_exact_fields(
        snapshot_value, "normalizedSnapshot", NORMALIZED_SNAPSHOT_FIELDS, errors
    )
    if snapshot is None:
        return None

    if snapshot.get("schemaVersion") != 1:
        add_error(errors, "normalizedSnapshot.schemaVersion", "must be 1")
    source = require_exact_fields(
        snapshot.get("source"),
        "normalizedSnapshot.source",
        NORMALIZED_SNAPSHOT_SOURCE_FIELDS,
        errors,
    )
    if source is not None:
        for field, expected in (
            ("publisher", "Korea Forest Service"),
            ("page", OFFICIAL_SOURCE_URL),
            ("endpoint", OFFICIAL_ENDPOINT),
            ("table", OFFICIAL_DATASET),
            ("query", OFFICIAL_QUERY),
            ("sourceCoordinateReferenceSystem", OFFICIAL_SOURCE_CRS),
            ("targetCoordinateReferenceSystem", "EPSG:4326"),
            ("retrievedAt", manifest_source.get("retrievedAt")),
        ):
            if source.get(field) != expected:
                add_error(
                    errors,
                    f"normalizedSnapshot.source.{field}",
                    f"must be '{expected}'",
                )
        if not valid_sha256(source.get("rawSHA256")):
            add_error(
                errors,
                "normalizedSnapshot.source.rawSHA256",
                "must be a lowercase 64-character SHA-256",
            )
        elif source.get("rawSHA256") != manifest_source.get("sha256"):
            add_error(
                errors,
                "normalizedSnapshot.source.rawSHA256",
                "must match source.sha256",
            )

    if snapshot.get("recordCount") != ENTRY_COUNT:
        add_error(errors, "normalizedSnapshot.recordCount", f"must be {ENTRY_COUNT}")
    if not valid_sha256(snapshot.get("recordsSHA256")):
        add_error(
            errors,
            "normalizedSnapshot.recordsSHA256",
            "must be a lowercase 64-character SHA-256",
        )

    records = snapshot.get("records")
    if type(records) is not list:
        add_error(errors, "normalizedSnapshot.records", "must be an array")
        return None
    if len(records) != ENTRY_COUNT:
        add_error(
            errors,
            "normalizedSnapshot.records",
            f"must contain exactly {ENTRY_COUNT} records",
        )

    try:
        canonical_records = json.dumps(
            records,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        add_error(
            errors,
            "normalizedSnapshot.records",
            f"cannot be canonically hashed: {error}",
        )
    else:
        if snapshot.get("recordsSHA256") != hashlib.sha256(canonical_records).hexdigest():
            add_error(
                errors,
                "normalizedSnapshot.recordsSHA256",
                "does not match the canonical normalized records",
            )

    normalized_records: list[dict[str, Any]] = []
    records_are_valid = len(records) == ENTRY_COUNT
    for index, record in enumerate(records):
        path = f"normalizedSnapshot.records[{index}]"
        record_object = require_exact_fields(record, path, NORMALIZED_RECORD_FIELDS, errors)
        if record_object is None:
            records_are_valid = False
            continue
        normalized_records.append(record_object)

        expected_id = index + 1
        if type(record_object.get("officialMountainID")) is not int:
            add_error(errors, f"{path}.officialMountainID", "must be an integer")
            records_are_valid = False
        elif record_object.get("officialMountainID") != expected_id:
            add_error(
                errors,
                f"{path}.officialMountainID",
                f"must be {expected_id} in official ID order",
            )
            records_are_valid = False

        name = record_object.get("name")
        if not isinstance(name, str) or not name or name != name.strip():
            add_error(
                errors,
                f"{path}.name",
                "must be a non-empty, trimmed official mountain name",
            )
            records_are_valid = False

        elevation = record_object.get("elevationMeters")
        if not valid_number(elevation):
            add_error(errors, f"{path}.elevationMeters", "must be finite")
            records_are_valid = False

        administrative_code = record_object.get("administrativeCode")
        if (
            not isinstance(administrative_code, str)
            or ADMINISTRATIVE_CODE_PATTERN.fullmatch(administrative_code) is None
        ):
            add_error(
                errors,
                f"{path}.administrativeCode",
                "must be an 8-digit administrative code",
            )
            records_are_valid = False
        elif broad_region_for(administrative_code) is None:
            add_error(
                errors,
                f"{path}.administrativeCode",
                "must map to a supported broad region",
            )
            records_are_valid = False

        administrative_name = record_object.get("administrativeName")
        if (
            not isinstance(administrative_name, str)
            or administrative_name != administrative_name.strip()
        ):
            add_error(
                errors,
                f"{path}.administrativeName",
                "must be a trimmed administrative name",
            )
            records_are_valid = False

        point = require_exact_fields(
            record_object.get("representativePoint"),
            f"{path}.representativePoint",
            NORMALIZED_POINT_FIELDS,
            errors,
        )
        if point is None:
            records_are_valid = False
            continue
        if point.get("epsg") != 4326:
            add_error(errors, f"{path}.representativePoint.epsg", "must be 4326")
            records_are_valid = False
        longitude = point.get("longitude")
        latitude = point.get("latitude")
        if not valid_number(longitude) or not 124.0 <= longitude <= 132.0:
            add_error(
                errors,
                f"{path}.representativePoint.longitude",
                "must be a finite South Korea longitude",
            )
            records_are_valid = False
        if not valid_number(latitude) or not 33.0 <= latitude <= 39.5:
            add_error(
                errors,
                f"{path}.representativePoint.latitude",
                "must be a finite South Korea latitude",
            )
            records_are_valid = False

    if not records_are_valid:
        return None
    return normalized_records


def validate_snapshot_catalog_binding(
    normalized_records: list[dict[str, Any]], catalog_value: Any, errors: list[str]
) -> None:
    if type(catalog_value) is not dict:
        return
    catalog_entries = catalog_value.get("entries")
    if (
        type(catalog_entries) is not list
        or len(catalog_entries) != ENTRY_COUNT
        or len(normalized_records) != ENTRY_COUNT
    ):
        return

    for index, normalized_record in enumerate(normalized_records):
        catalog_entry = catalog_entries[index]
        if type(catalog_entry) is not dict:
            continue
        path = f"catalog.entries[{index}]"
        official_reference = str(normalized_record["officialMountainID"])
        if catalog_entry.get("sourceReference") != official_reference:
            add_error(
                errors,
                f"{path}.sourceReference",
                "must derive from the normalized official mountain ID in order",
            )
        if catalog_entry.get("name") != normalized_record["name"]:
            add_error(
                errors,
                f"{path}.name",
                "must match the normalized official mountain name",
            )

        source_administrative_code = normalized_record["administrativeCode"]
        catalog_administrative_code = catalog_entry.get("administrativeCode")
        if catalog_administrative_code != source_administrative_code:
            add_error(
                errors,
                f"{path}.administrativeCode",
                "must match the normalized official administrative code",
            )
        if broad_region_for(catalog_administrative_code) != broad_region_for(
            source_administrative_code
        ):
            add_error(
                errors,
                f"{path}.administrativeCode",
                "must derive the same broad region as the normalized official record",
            )

        representative_point = normalized_record["representativePoint"]
        if not representative_coordinate_matches(
            catalog_entry.get("longitude"), representative_point["longitude"]
        ):
            add_error(
                errors,
                f"{path}.longitude",
                "must match the normalized official representative point within 1e-7 degrees",
            )
        if not representative_coordinate_matches(
            catalog_entry.get("latitude"), representative_point["latitude"]
        ):
            add_error(
                errors,
                f"{path}.latitude",
                "must match the normalized official representative point within 1e-7 degrees",
            )


def validate_catalog(
    catalog_value: Any, dataset_version: Any, expected_status: str, errors: list[str]
) -> set[str]:
    catalog = require_exact_fields(catalog_value, "catalog", CATALOG_FIELDS, errors)
    if catalog is None:
        return set()

    if catalog.get("schemaVersion") != SCHEMA_VERSION:
        add_error(errors, "catalog.schemaVersion", f"must be '{SCHEMA_VERSION}'")
    if catalog.get("datasetVersion") != dataset_version:
        add_error(errors, "catalog.datasetVersion", "must match manifest.datasetVersion")
    if catalog.get("status") != expected_status:
        add_error(errors, "catalog.status", f"must be '{expected_status}'")
    if catalog.get("coordinateReferenceSystem") != "WGS84":
        add_error(errors, "catalog.coordinateReferenceSystem", "must be 'WGS84'")

    entries = catalog.get("entries")
    if type(entries) is not list:
        add_error(errors, "catalog.entries", "must be an array")
        return set()
    if len(entries) != ENTRY_COUNT:
        add_error(errors, "catalog.entries", f"must contain exactly {ENTRY_COUNT} entries")

    ids: set[str] = set()
    for index, entry in enumerate(entries):
        path = f"catalog.entries[{index}]"
        entry_object = require_exact_fields(entry, path, CATALOG_ENTRY_FIELDS, errors)
        if entry_object is None:
            continue

        expected_reference = str(index + 1)
        source_reference = entry_object.get("sourceReference")
        if source_reference != expected_reference:
            add_error(errors, f"{path}.sourceReference", f"must be '{expected_reference}'")
        entry_id = entry_object.get("id")
        if not isinstance(entry_id, str) or OPAQUE_ID_PATTERN.fullmatch(entry_id) is None:
            add_error(errors, f"{path}.id", "must be an opaque hkr_mtn_<32 lowercase hex> ID")
        else:
            if entry_id in ids:
                add_error(errors, f"{path}.id", "must not duplicate another entry")
            ids.add(entry_id)
            if entry_id != opaque_id_for(expected_reference):
                add_error(errors, f"{path}.id", "must be derived from its official source reference")

        name = entry_object.get("name")
        if not isinstance(name, str) or not name.strip():
            add_error(errors, f"{path}.name", "must be a non-empty string")

        administrative_code = entry_object.get("administrativeCode")
        if (
            not isinstance(administrative_code, str)
            or ADMINISTRATIVE_CODE_PATTERN.fullmatch(administrative_code) is None
        ):
            add_error(errors, f"{path}.administrativeCode", "must be an 8-digit administrative code")
        elif broad_region_for(administrative_code) is None:
            add_error(errors, f"{path}.administrativeCode", "must map to a supported broad region")

        longitude = entry_object.get("longitude")
        latitude = entry_object.get("latitude")
        if not valid_number(longitude) or not 124.0 <= longitude <= 132.0:
            add_error(errors, f"{path}.longitude", "must be a finite South Korea longitude")
        if not valid_number(latitude) or not 33.0 <= latitude <= 39.5:
            add_error(errors, f"{path}.latitude", "must be a finite South Korea latitude")

    if len(ids) != ENTRY_COUNT:
        add_error(errors, "catalog.entries", f"must contain exactly {ENTRY_COUNT} unique IDs")
    return ids


def validate_legacy_document(
    legacy_value: Any,
    dataset_version: Any,
    expected_status: str,
    catalog_ids: set[str],
    errors: list[str],
) -> None:
    legacy = require_exact_fields(legacy_value, "legacyResource", LEGACY_DOCUMENT_FIELDS, errors)
    if legacy is None:
        return

    if legacy.get("schemaVersion") != SCHEMA_VERSION:
        add_error(errors, "legacyResource.schemaVersion", f"must be '{SCHEMA_VERSION}'")
    if legacy.get("datasetVersion") != dataset_version:
        add_error(errors, "legacyResource.datasetVersion", "must match manifest.datasetVersion")
    if legacy.get("status") != expected_status:
        add_error(errors, "legacyResource.status", f"must be '{expected_status}'")

    entries = legacy.get("entries")
    if type(entries) is not list:
        add_error(errors, "legacyResource.entries", "must be an array")
        return
    if len(entries) != ENTRY_COUNT:
        add_error(errors, "legacyResource.entries", f"must contain exactly {ENTRY_COUNT} mappings")

    legacy_ids: set[str] = set()
    current_ids: set[str] = set()
    for index, mapping in enumerate(entries):
        path = f"legacyResource.entries[{index}]"
        mapping_object = require_exact_fields(mapping, path, LEGACY_ENTRY_FIELDS, errors)
        if mapping_object is None:
            continue

        expected_reference = str(index + 1)
        legacy_id = mapping_object.get("legacyID")
        current_id = mapping_object.get("currentID")
        if legacy_id != expected_reference:
            add_error(errors, f"{path}.legacyID", f"must be '{expected_reference}'")
        elif legacy_id in legacy_ids:
            add_error(errors, f"{path}.legacyID", "must not duplicate another legacy ID")
        else:
            legacy_ids.add(legacy_id)

        expected_current_id = opaque_id_for(expected_reference)
        if not isinstance(current_id, str):
            add_error(errors, f"{path}.currentID", "must be a string")
        elif current_id != expected_current_id:
            add_error(errors, f"{path}.currentID", "must be derived from its official source reference")
        elif current_id in current_ids:
            add_error(errors, f"{path}.currentID", "must not duplicate another current ID")
        else:
            current_ids.add(current_id)
        if not isinstance(current_id, str) or current_id not in catalog_ids:
            add_error(errors, f"{path}.currentID", "must resolve to a catalog ID")

    if legacy_ids != {str(index) for index in range(1, ENTRY_COUNT + 1)}:
        add_error(errors, "legacyResource.entries", "must cover official source references 1 through 100")
    if current_ids != catalog_ids:
        add_error(errors, "legacyResource.entries", "must map one-to-one to the catalog IDs")


def validate_resources(
    manifest_path: Path,
    manifest: dict[str, Any],
    mode: str,
    errors: list[str],
) -> None:
    source = manifest.get("source")
    normalized_records: list[dict[str, Any]] | None = None
    if type(source) is dict:
        raw_resource: bytes | None = None
        normalized_snapshot: Any | None = None
        validated_normalized_records: list[dict[str, Any]] | None = None

        raw_resource_path = resolve_repository_resource(source, "rawResource", errors)
        if raw_resource_path is not None:
            raw_resource = read_resource_bytes(
                raw_resource_path, "source.rawResource", errors
            )
            if (
                raw_resource is not None
                and source.get("sha256") != hashlib.sha256(raw_resource).hexdigest()
            ):
                add_error(
                    errors,
                    "source.sha256",
                    "does not match the actual raw official-source resource",
                )

        normalized_snapshot_path = resolve_repository_resource(
            source, "normalizedSnapshotPath", errors
        )
        if normalized_snapshot_path is not None:
            normalized_snapshot_document = read_json_document(
                normalized_snapshot_path, "normalizedSnapshot", errors
            )
            if normalized_snapshot_document is not None:
                normalized_snapshot, _ = normalized_snapshot_document
                validated_normalized_records = validate_normalized_snapshot(
                    normalized_snapshot, source, errors
                )

        retrieved_at = source.get("retrievedAt")
        if raw_resource is not None and normalized_snapshot is not None:
            if not isinstance(retrieved_at, str):
                add_error(
                    errors,
                    "source.retrievedAt",
                    "must be a string to re-run the shared fetch normalizer",
                )
            else:
                recomputed_snapshot = recompute_normalized_snapshot(
                    raw_resource, retrieved_at, errors
                )
                if recomputed_snapshot is not None:
                    if recomputed_snapshot != normalized_snapshot:
                        add_error(
                            errors,
                            "normalizedSnapshot",
                            "must exactly match the deterministic normalization of source.rawResource",
                        )
                    else:
                        normalized_records = validated_normalized_records

    catalog_document = read_json_document(
        manifest_path.parent / f"{CATALOG_RESOURCE}.json", "catalog", errors
    )
    legacy_document = read_json_document(
        manifest_path.parent / f"{LEGACY_RESOURCE}.json", "legacyResource", errors
    )

    expected_status = CANDIDATE_STATUS if mode == "candidate" else RELEASE_STATUS
    catalog_ids: set[str] = set()
    if catalog_document is not None:
        catalog, catalog_data = catalog_document
        content = manifest.get("content")
        if type(content) is dict:
            actual_hash = hashlib.sha256(catalog_data).hexdigest()
            if content.get("sha256") != actual_hash:
                add_error(errors, "content.sha256", "does not match the actual catalog resource")
        catalog_ids = validate_catalog(
            catalog, manifest.get("datasetVersion"), expected_status, errors
        )
        if normalized_records is not None:
            validate_snapshot_catalog_binding(normalized_records, catalog, errors)

    if legacy_document is not None:
        legacy, legacy_data = legacy_document
        provenance = manifest.get("legacy")
        if type(provenance) is dict:
            actual_hash = hashlib.sha256(legacy_data).hexdigest()
            if provenance.get("sha256") != actual_hash:
                add_error(errors, "legacy.sha256", "does not match the actual legacy resource")
        validate_legacy_document(
            legacy,
            manifest.get("datasetVersion"),
            LEGACY_CANDIDATE_STATUS if mode == "candidate" else RELEASE_STATUS,
            catalog_ids,
            errors,
        )

def validate_m1_manifest(manifest: Any, mode: str, manifest_path: Path) -> list[str]:
    errors: list[str] = []
    root = require_exact_fields(manifest, "manifest", M1_ROOT_FIELDS, errors)
    if root is None:
        return errors

    expected_status = CANDIDATE_STATUS if mode == "candidate" else RELEASE_STATUS
    if root.get("schemaVersion") != SCHEMA_VERSION:
        add_error(errors, "schemaVersion", f"must be '{SCHEMA_VERSION}'")
    dataset_version = root.get("datasetVersion")
    if not isinstance(dataset_version, str) or SEMVER_PATTERN.fullmatch(dataset_version) is None:
        add_error(errors, "datasetVersion", "must be a semantic version")
    if (
        mode == "release"
        and isinstance(dataset_version, str)
        and SEMVER_PATTERN.fullmatch(dataset_version) is not None
        and is_prerelease_semver(dataset_version)
    ):
        add_error(errors, "datasetVersion", "must not be a prerelease in release mode")
    if mode == "candidate" and dataset_version != M1_DATASET_VERSION:
        add_error(errors, "datasetVersion", f"must be '{M1_DATASET_VERSION}' for M1")
    if root.get("status") != expected_status:
        add_error(errors, "status", f"must be '{expected_status}' in {mode} mode")
    if root.get("entryCount") != ENTRY_COUNT:
        add_error(errors, "entryCount", f"must be {ENTRY_COUNT}")

    source = validate_source(root.get("source"), mode, errors)
    validate_content(root.get("content"), mode, errors)
    validate_legacy_provenance(root.get("legacy"), mode, errors)
    if mode == "candidate":
        validate_candidate_review(root.get("review"), errors)
    else:
        validate_release_review(
            root.get("review"),
            source.get("retrievedAt") if source is not None else None,
            errors,
        )
    validate_resources(manifest_path, root, mode, errors)
    return errors


def validate_manifest(manifest: Any, mode: str, manifest_path: Path) -> list[str]:
    if mode == "skeleton":
        errors: list[str] = []
        validate_m0_skeleton(manifest, errors)
        return errors
    return validate_m1_manifest(manifest, mode, manifest_path)


def default_manifest_path() -> Path:
    return (
        Path(__file__).resolve().parents[2]
        / "Packages/HikerDataset/Sources/HikerDataset/Resources/dataset-manifest.json"
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=default_manifest_path(),
        help="path to dataset-manifest.json",
    )
    parser.add_argument(
        "--mode",
        choices=("skeleton", "candidate", "release"),
        default="candidate",
        help="skeleton validates M0, candidate validates M1, release requires approval",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    read_errors: list[str] = []
    manifest_document = read_json_document(args.manifest, "manifest", read_errors)
    if manifest_document is None:
        print("dataset manifest validation failed:", file=sys.stderr)
        for error in read_errors:
            print(f"- {error}", file=sys.stderr)
        return 2

    manifest, _ = manifest_document
    errors = validate_manifest(manifest, args.mode, args.manifest)
    if errors:
        print("dataset manifest validation failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    print(f"dataset manifest is valid for {args.mode} mode: {args.manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
