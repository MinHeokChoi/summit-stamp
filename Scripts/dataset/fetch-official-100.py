#!/usr/bin/env python3
"""Fetch and normalize the Forest Service 100-famous-mountain GIS snapshot."""

from __future__ import annotations

import argparse
import hashlib
import json
from decimal import Decimal, InvalidOperation
import math
import os
import re
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.request import HTTPRedirectHandler, Request, build_opener

ENDPOINT = (
    "https://map.forest.go.kr/gis1/iserver/services/"
    "data-fdms/rest/data/featureResults.json?returnContent=true"
)
DATASET = "FDMS_BASE:TB_FGDI_FS_F100"
SOURCE_PAGE = "https://map.forest.go.kr/forest/?systype=appdata"
EXPECTED_FIELDS = (
    "SMID",
    "SMUSERID",
    "SMGEOMETRY",
    "OBJ_ID",
    "MNTN_ID",
    "MNTN_NM",
    "MNTN_HGHT",
    "PHTGR_NO",
    "EMNDN_CD",
    "EMNDN_NM",
)
SOURCE_CRS = "EPSG:5179"
TARGET_CRS = "EPSG:4326"
TARGET_EPSG_CODE = 4326
QUERY = "1=1"
MAX_RESPONSE_BYTES = 10 * 1024 * 1024
ADMINISTRATIVE_CODE_PATTERN = re.compile(r"^[0-9]{8}$")
OFFICIAL_ID_PATTERN = re.compile(r"^(?:[1-9]|[1-9][0-9]|100)$")
ELEVATION_PATTERN = re.compile(r"^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$")

class DuplicateKeyError(ValueError):
    """Raised when a JSON object repeats a field name."""


class RejectRedirectHandler(HTTPRedirectHandler):
    """Reject redirects so the preserved bytes come from the fixed endpoint."""

    def redirect_request(
        self,
        request: Request,
        file_pointer: Any,
        status_code: int,
        message: str,
        headers: Any,
        redirect_url: str,
    ) -> None:
        raise RuntimeError(
            f"Forest Service GIS redirect to {redirect_url!r} is not allowed"
        )


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"duplicate object field: {key}")
        result[key] = value
    return result


def reject_nonstandard_constant(value: str) -> None:
    raise ValueError(f"nonstandard JSON constant is not allowed: {value}")


def valid_json_number(value: Any) -> bool:
    return type(value) is int or (type(value) is float and math.isfinite(value))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--raw-output", type=Path, required=True)
    parser.add_argument(
        "--retrieved-at",
        required=True,
        help="ISO-8601 UTC timestamp recorded in the normalized snapshot",
    )
    parser.add_argument("--timeout", type=float, default=30.0)
    return parser.parse_args()


def validate_timestamp(value: str) -> str:
    if not value.endswith("Z"):
        raise ValueError("--retrieved-at must be an ISO-8601 UTC timestamp ending in Z")
    datetime.fromisoformat(value[:-1] + "+00:00")
    return value


def fetch(timeout: float) -> bytes:
    payload = json.dumps(
        {
            "datasetNames": [DATASET],
            "getFeatureMode": "SQL",
            "targetEpsgCode": TARGET_EPSG_CODE,
            "queryParameter": {"attributeFilter": QUERY},
        },
        separators=(",", ":"),
    ).encode("utf-8")
    request = Request(
        ENDPOINT,
        data=payload,
        method="POST",
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "HikerDatasetSnapshot/1.0",
        },
    )
    opener = build_opener(RejectRedirectHandler())
    with opener.open(request, timeout=timeout) as response:  # noqa: S310 - fixed HTTPS host
        if 300 <= response.status < 400:
            raise RuntimeError(
                f"Forest Service GIS redirect HTTP {response.status} is not allowed"
            )
        if response.status not in (200, 201):
            raise RuntimeError(f"Forest Service GIS returned HTTP {response.status}")
        raw = response.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError(
            f"Forest Service GIS response exceeds {MAX_RESPONSE_BYTES} byte limit"
        )
    return raw


def decode_response(raw: bytes) -> dict[str, Any]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("official GIS response must be UTF-8 JSON") from error
    try:
        document = json.loads(
            text,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_nonstandard_constant,
        )
    except DuplicateKeyError as error:
        raise ValueError(f"official GIS response has duplicate keys: {error}") from error
    except json.JSONDecodeError as error:
        raise ValueError(f"official GIS response is invalid JSON: {error}") from error
    except ValueError as error:
        raise ValueError(f"official GIS response is invalid JSON: {error}") from error
    if type(document) is not dict:
        raise ValueError("official GIS response must be an object")
    return document


def normalize(raw: bytes, retrieved_at: str) -> dict[str, Any]:
    document = decode_response(raw)
    features = document.get("features")
    if (
        type(document.get("featureCount")) is not int
        or document["featureCount"] != 100
        or type(features) is not list
        or len(features) != 100
    ):
        raise ValueError("official GIS response must contain exactly 100 features")

    records: list[dict[str, Any]] = []
    ids: set[int] = set()
    for index, feature in enumerate(features):
        if type(feature) is not dict:
            raise ValueError(f"feature {index} must be an object")
        field_names = feature.get("fieldNames")
        if type(field_names) is not list or field_names != list(EXPECTED_FIELDS):
            raise ValueError(f"feature {index} has an unexpected field schema")
        values = feature.get("fieldValues")
        if type(values) is not list or len(values) != len(EXPECTED_FIELDS):
            raise ValueError(f"feature {index} has invalid field values")
        fields = dict(zip(EXPECTED_FIELDS, values, strict=True))

        official_id = fields["MNTN_ID"]
        if (
            type(official_id) is not str
            or OFFICIAL_ID_PATTERN.fullmatch(official_id) is None
        ):
            raise ValueError(f"feature {index} has an invalid official mountain ID")
        mountain_id = int(official_id)
        if mountain_id in ids:
            raise ValueError(f"duplicate official mountain ID: {mountain_id}")
        ids.add(mountain_id)

        elevation = fields["MNTN_HGHT"]
        if type(elevation) is not str or ELEVATION_PATTERN.fullmatch(elevation) is None:
            raise ValueError(f"feature {mountain_id} has invalid elevation")
        try:
            elevation_decimal = Decimal(elevation)
            elevation_meters = float(elevation_decimal)
        except (InvalidOperation, OverflowError, ValueError) as error:
            raise ValueError(f"feature {mountain_id} has invalid elevation") from error
        if (
            not math.isfinite(elevation_meters)
            or Decimal.from_float(elevation_meters) != elevation_decimal
        ):
            raise ValueError(
                f"feature {mountain_id} elevation cannot be represented exactly"
            )

        name_value = fields["MNTN_NM"]
        administrative_code = fields["EMNDN_CD"]
        administrative_name = fields["EMNDN_NM"]
        if type(name_value) is not str or not name_value.strip():
            raise ValueError(f"feature {mountain_id} has an invalid mountain name")
        if (
            type(administrative_code) is not str
            or ADMINISTRATIVE_CODE_PATTERN.fullmatch(administrative_code) is None
        ):
            raise ValueError(
                f"feature {mountain_id} has an invalid administrative code"
            )
        if type(administrative_name) is not str:
            raise ValueError(
                f"feature {mountain_id} has an invalid administrative name"
            )

        geometry = feature.get("geometry")
        if type(geometry) is not dict:
            raise ValueError(f"feature {mountain_id} has invalid geometry")
        points = geometry.get("points")
        if type(points) is not list or len(points) != 1 or type(points[0]) is not dict:
            raise ValueError(f"feature {mountain_id} must have one representative point")
        longitude = points[0].get("x")
        latitude = points[0].get("y")
        if not valid_json_number(longitude):
            raise ValueError(f"feature {mountain_id} has invalid longitude")
        if not valid_json_number(latitude):
            raise ValueError(f"feature {mountain_id} has invalid latitude")
        if not 124.0 <= longitude <= 132.0 or not 33.0 <= latitude <= 39.5:
            raise ValueError(f"feature {mountain_id} point falls outside South Korea")

        records.append(
            {
                "officialMountainID": mountain_id,
                "name": name_value.strip(),
                "elevationMeters": elevation_meters,
                "administrativeCode": administrative_code,
                "administrativeName": administrative_name.strip(),
                "representativePoint": {
                    "latitude": latitude,
                    "longitude": longitude,
                    "epsg": TARGET_EPSG_CODE,
                },
            }
        )

    if ids != set(range(1, 101)):
        raise ValueError("official mountain IDs must be exactly 1 through 100")
    records.sort(key=lambda record: record["officialMountainID"])
    canonical_records = json.dumps(
        records, ensure_ascii=False, separators=(",", ":"), sort_keys=True, allow_nan=False
    ).encode("utf-8")
    return {
        "schemaVersion": 1,
        "source": {
            "publisher": "Korea Forest Service",
            "page": SOURCE_PAGE,
            "endpoint": ENDPOINT,
            "table": DATASET,
            "query": QUERY,
            "sourceCoordinateReferenceSystem": SOURCE_CRS,
            "targetCoordinateReferenceSystem": TARGET_CRS,
            "retrievedAt": retrieved_at,
            "rawSHA256": hashlib.sha256(raw).hexdigest(),
        },
        "recordCount": len(records),
        "recordsSHA256": hashlib.sha256(canonical_records).hexdigest(),
        "records": records,
    }


def stage_bytes(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as temporary:
            temporary.write(data)
            temporary.flush()
            os.fsync(temporary.fileno())
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise
    return Path(temporary_name)


def encode_json(document: dict[str, Any]) -> bytes:
    return (json.dumps(document, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode(
        "utf-8"
    )


def backup_output(path: Path) -> Path | None:
    if not os.path.lexists(path):
        return None

    descriptor, backup_name = tempfile.mkstemp(prefix=f".{path.name}.backup.", dir=path.parent)
    os.close(descriptor)
    try:
        os.replace(path, backup_name)
    except BaseException:
        try:
            os.unlink(backup_name)
        except FileNotFoundError:
            pass
        raise
    return Path(backup_name)


def remove_staged_file(path: Path) -> None:
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


def restore_output(path: Path, backup: Path | None, published: bool) -> None:
    if backup is not None:
        os.replace(backup, path)
    elif published:
        os.unlink(path)


def publish_generation(
    raw_output: Path,
    raw_staged: Path,
    output: Path,
    normalized_staged: Path,
) -> None:
    raw_backup: Path | None = None
    normalized_backup: Path | None = None
    raw_published = False
    normalized_published = False

    try:
        raw_backup = backup_output(raw_output)
        normalized_backup = backup_output(output)
        os.replace(raw_staged, raw_output)
        raw_published = True
        os.replace(normalized_staged, output)
        normalized_published = True
    except BaseException as error:
        rollback_errors: list[BaseException] = []
        for path, backup, published in (
            (raw_output, raw_backup, raw_published),
            (output, normalized_backup, normalized_published),
        ):
            try:
                restore_output(path, backup, published)
            except BaseException as rollback_error:
                rollback_errors.append(rollback_error)
        if rollback_errors:
            raise RuntimeError(
                "failed to publish dataset generation and restore the prior generation"
            ) from error
        raise
    else:
        if raw_backup is not None:
            remove_staged_file(raw_backup)
        if normalized_backup is not None:
            remove_staged_file(normalized_backup)
    finally:
        remove_staged_file(raw_staged)
        remove_staged_file(normalized_staged)


def main() -> int:
    args = parse_args()
    if args.raw_output.resolve() == args.output.resolve():
        raise ValueError("--raw-output and --output must be different files")
    retrieved_at = validate_timestamp(args.retrieved_at)
    raw = fetch(args.timeout)
    normalized = normalize(raw, retrieved_at)
    raw_staged = stage_bytes(args.raw_output, raw)
    try:
        normalized_staged = stage_bytes(args.output, encode_json(normalized))
    except BaseException:
        remove_staged_file(raw_staged)
        raise
    publish_generation(args.raw_output, raw_staged, args.output, normalized_staged)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
