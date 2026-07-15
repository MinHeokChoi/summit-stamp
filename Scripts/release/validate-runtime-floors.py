#!/usr/bin/env python3
"""Validate immutable beta or production runtime floors without waiver paths."""

from __future__ import annotations

import hashlib
import json
import math
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
import re
import secrets
import stat
import subprocess
import sys
from typing import Any, NoReturn


class FloorError(Exception):
    pass


def fail() -> NoReturn:
    raise FloorError


SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
COMMIT_RE = re.compile(r"^[a-f0-9]{40}(?:[a-f0-9]{24})?$")
TAG_RE = re.compile(r"^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
SENSITIVE_RE = re.compile(
    r"(?i)(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|\b(?:gh[pousr]|github_pat)_[A-Za-z0-9_]{20,}\b|"
    r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b|\bAKIA[0-9A-Z]{16}\b|"
    r"\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b|"
    r"(?:authorization|bearer|password|secret|token|cookie|credential)\s*[:=])"
)
EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
PHONE_RE = re.compile(r"(?<![0-9])\+[1-9][0-9]{7,14}(?![0-9])")

BETA_ID = "REL-005"
PRODUCTION_IDS = frozenset({"REL-011-05", "REL-011-25", "REL-011-50", "REL-011-100"})
SCHEMA_PATH = "Docs/evidence/schemas/threshold-ratification.schema.json"
ALLOWED_PROVIDERS = frozenset({"app-store-connect", "supabase", "telemetry", "protected-synthetics"})
EXCLUSION_FIELDS = frozenset(
    {"userCancelled", "intentionalOfflinePending", "genericBlockDenial", "intendedFailClosedUnavailable"}
)
STATIC_BETA_MINIMUMS = {
    "minimumWindowHours": 168.0,
    "crashFreeSessionsPercent": 99.5,
    "authSuccessPercent": 99.0,
    "bootstrapSuccessPercent": 99.0,
    "manualMutationSuccessPercent": 99.0,
}
STATIC_BETA_MAXIMUMS = {"mapP95Seconds": 2.5, "bootstrapP95Seconds": 3.0}
STATIC_BETA_ZERO = frozenset({"p0Count", "unresolvedP1Count", "authBypassCount", "rawGPSPersistenceCount"})
STATIC_PRODUCTION_MINIMUMS = {
    "minimumWindowHours": 24.0,
    "crashFreeSessionsPercent": 99.7,
    "crashFreeUsersPercent": 99.5,
    "mutationSuccessPercent": 99.5,
}
STATIC_PRODUCTION_MAXIMUMS = {
    "server5xxPercent": 0.5,
    "manualOnlineAckP95Seconds": 2.0,
    "revokeEventP95Seconds": 5.0,
    "failClosedLeaseSeconds": 30.0,
}
STATIC_PRODUCTION_ZERO = frozenset(
    {
        "p0Count",
        "unresolvedP1Count",
        "directDMLExposureCount",
        "privacyExposureCount",
        "authBypassCount",
        "revocationExposureCount",
        "rawGPSPersistenceCount",
    }
)


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def sha256(value: bytes | Any) -> str:
    return hashlib.sha256(value if isinstance(value, bytes) else canonical_bytes(value)).hexdigest()


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail()
        result[key] = value
    return result


def reject_non_standard_number(_value: str) -> None:
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
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_non_standard_number,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        fail()
    reject_nonfinite(value)
    return value


def parse_arguments(arguments: list[str]) -> dict[str, str]:
    options = {
        "--id": "id",
        "--source-manifest": "source_manifest",
        "--threshold": "threshold",
        "--schema": "schema",
        "--output": "output",
    }
    values: dict[str, str] = {}
    index = 0
    while index < len(arguments):
        option = arguments[index]
        if option not in options or index + 1 >= len(arguments):
            fail()
        value = arguments[index + 1]
        name = options[option]
        if name in values or not value or value.startswith("--"):
            fail()
        values[name] = value
        index += 2
    if set(values) != set(options.values()):
        fail()
    return values


def reject_sensitive_text(value: str) -> None:
    if (
        not value
        or len(value) > 4096
        or any(ord(character) < 32 or ord(character) > 126 for character in value)
        or SENSITIVE_RE.search(value) is not None
        or EMAIL_RE.search(value) is not None
        or PHONE_RE.search(value) is not None
    ):
        fail()


def reject_sensitive_data(value: Any) -> None:
    if isinstance(value, str):
        reject_sensitive_text(value)
    elif isinstance(value, list):
        for item in value:
            reject_sensitive_data(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            reject_sensitive_text(key)
            reject_sensitive_data(item)
    elif value is None or type(value) in {bool, int, float}:
        return
    else:
        fail()


def finite_number(value: Any) -> float:
    if type(value) not in {int, float}:
        fail()
    try:
        result = float(value)
    except (TypeError, ValueError, OverflowError):
        fail()
    if not math.isfinite(result):
        fail()
    return result


def positive_integer(value: Any) -> int:
    if type(value) is not int or value <= 0:
        fail()
    return value


def nonnegative_integer(value: Any) -> int:
    if type(value) is not int or value < 0:
        fail()
    return value


def parse_timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or TIMESTAMP_RE.fullmatch(value) is None:
        fail()
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        fail()


def require_sha(value: Any) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        fail()
    return value


def relative_parts(value: str) -> tuple[str, ...]:
    path = PurePosixPath(value)
    if (
        not value
        or "\\" in value
        or path.is_absolute()
        or path.as_posix() != value
        or not path.parts
        or any(part in {".", ".."} for part in path.parts)
    ):
        fail()
    return path.parts


def repository_root() -> Path:
    result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"], check=False, capture_output=True, stdin=subprocess.DEVNULL
    )
    try:
        root = Path(result.stdout.decode("utf-8", "strict").strip()).resolve(strict=True)
    except (OSError, UnicodeError):
        fail()
    if result.returncode != 0 or not root.is_dir():
        fail()
    return root


def read_regular(root: Path, relative: str, limit: int = 1024 * 1024) -> bytes:
    parts = relative_parts(relative)
    directory = -1
    descriptor = -1
    try:
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        for part in parts[:-1]:
            next_directory = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = next_directory
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size <= 0 or metadata.st_size > limit:
            fail()
        result = bytearray()
        while len(result) <= limit:
            chunk = os.read(descriptor, min(65536, limit + 1 - len(result)))
            if not chunk:
                break
            result.extend(chunk)
        if len(result) == 0 or len(result) > limit:
            fail()
        return bytes(result)
    except OSError:
        fail()
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if directory >= 0:
            os.close(directory)


def canonical_document(root: Path, relative: str) -> tuple[dict[str, Any], bytes, str]:
    raw = read_regular(root, relative)
    document = parse_json(raw)
    if not isinstance(document, dict):
        fail()
    canonical = canonical_bytes(document) + b"\n"
    if raw != canonical:
        fail()
    reject_sensitive_data(document)
    return document, canonical, sha256(canonical)


def verify_sidecar(root: Path, relative: str, digest: str) -> None:
    expected = f"{digest}  {relative}\n".encode("ascii")
    if read_regular(root, f"{relative}.sha256", 256) != expected:
        fail()


def property_definition(schema: dict[str, Any], period: str, field: str) -> dict[str, Any]:
    definitions = schema.get("$defs")
    if not isinstance(definitions, dict):
        fail()
    definition_name = "betaThresholds" if period == "beta" else "productionThresholds"
    definition = definitions.get(definition_name)
    if not isinstance(definition, dict) or definition.get("type") != "object" or definition.get("additionalProperties") is not False:
        fail()
    properties = definition.get("properties")
    if not isinstance(properties, dict) or not isinstance(properties.get(field), dict):
        fail()
    return properties[field]


def validate_schema_floor(schema: dict[str, Any], period: str, minimums: dict[str, float], maximums: dict[str, float], zeros: frozenset[str]) -> tuple[dict[str, float], dict[str, float]]:
    threshold_properties = schema.get("properties")
    if not isinstance(threshold_properties, dict) or not isinstance(threshold_properties.get("thresholds"), dict):
        fail()
    thresholds = threshold_properties["thresholds"]
    if (
        thresholds.get("type") != "object"
        or thresholds.get("additionalProperties") is not False
        or set(thresholds.get("required", [])) != {"beta", "production"}
    ):
        fail()
    period_properties = thresholds.get("properties")
    if not isinstance(period_properties, dict) or set(period_properties) != {"beta", "production"}:
        fail()
    reference = f"#/$defs/{'betaThresholds' if period == 'beta' else 'productionThresholds'}"
    if not isinstance(period_properties, dict) or period_properties.get(period) != {"$ref": reference}:
        fail()
    definition = schema.get("$defs", {}).get("betaThresholds" if period == "beta" else "productionThresholds")
    expected_fields = set(minimums).union(maximums).union(zeros)
    if (
        not isinstance(definition, dict)
        or set(definition.get("required", [])) != expected_fields
        or not isinstance(definition.get("properties"), dict)
        or set(definition["properties"]) != expected_fields
    ):
        fail()
    minimum_bounds: dict[str, float] = {}
    maximum_bounds: dict[str, float] = {}
    for field, static_value in minimums.items():
        item = property_definition(schema, period, field)
        bound = finite_number(item.get("minimum"))
        if item.get("type") != "number" or bound < static_value:
            fail()
        minimum_bounds[field] = bound
    for field, static_value in maximums.items():
        item = property_definition(schema, period, field)
        bound_value = item.get("exclusiveMaximum") if field == "server5xxPercent" else item.get("maximum")
        bound = finite_number(bound_value)
        if item.get("type") != "number" or bound > static_value:
            fail()
        maximum_bounds[field] = bound
    zero_definition = schema.get("$defs", {}).get("zero")
    if not isinstance(zero_definition, dict) or zero_definition.get("type") != "integer" or zero_definition.get("const") != 0:
        fail()
    for field in zeros:
        if property_definition(schema, period, field) != {"$ref": "#/$defs/zero"}:
            fail()
    return minimum_bounds, maximum_bounds


def validate_schema(schema: dict[str, Any]) -> dict[str, tuple[dict[str, float], dict[str, float]]]:
    expected_top = {"$schema", "$id", "title", "description", "type", "required", "additionalProperties", "properties", "$defs"}
    expected_properties = {"schemaVersion", "artifactType", "id", "tag", "commit", "approvalSHA256", "createdAt", "thresholds"}
    definitions = schema.get("$defs")
    properties = schema.get("properties")
    if (
        set(schema) != expected_top
        or schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema"
        or schema.get("$id") != "https://hiker.invalid/evidence/schemas/threshold-ratification/v1"
        or schema.get("type") != "object"
        or schema.get("additionalProperties") is not False
        or set(schema.get("required", [])) != expected_properties
        or not isinstance(properties, dict)
        or set(properties) != expected_properties
        or not isinstance(definitions, dict)
        or set(definitions) != {"sha256", "utcTimestamp", "zero", "betaThresholds", "productionThresholds"}
    ):
        fail()
    beta_bounds = validate_schema_floor(schema, "beta", STATIC_BETA_MINIMUMS, STATIC_BETA_MAXIMUMS, STATIC_BETA_ZERO)
    production_bounds = validate_schema_floor(
        schema, "production", STATIC_PRODUCTION_MINIMUMS, STATIC_PRODUCTION_MAXIMUMS, STATIC_PRODUCTION_ZERO
    )
    return {"beta": beta_bounds, "production": production_bounds}


def validate_threshold_document(
    document: dict[str, Any],
    bounds: dict[str, tuple[dict[str, float], dict[str, float]]],
) -> dict[str, dict[str, float | int]]:
    expected_fields = {"schemaVersion", "artifactType", "id", "tag", "commit", "approvalSHA256", "createdAt", "thresholds"}
    if set(document) != expected_fields or (
        document.get("schemaVersion") != 1
        or document.get("artifactType") != "threshold-ratification"
        or document.get("id") != "OPS-005"
        or not isinstance(document.get("tag"), str)
        or TAG_RE.fullmatch(document["tag"]) is None
        or not isinstance(document.get("commit"), str)
        or COMMIT_RE.fullmatch(document["commit"]) is None
    ):
        fail()
    require_sha(document.get("approvalSHA256"))
    parse_timestamp(document.get("createdAt"))
    thresholds = document.get("thresholds")
    if not isinstance(thresholds, dict) or set(thresholds) != {"beta", "production"}:
        fail()
    result: dict[str, dict[str, float | int]] = {}
    for period, minimums, maximums, zeros in (
        ("beta", STATIC_BETA_MINIMUMS, STATIC_BETA_MAXIMUMS, STATIC_BETA_ZERO),
        ("production", STATIC_PRODUCTION_MINIMUMS, STATIC_PRODUCTION_MAXIMUMS, STATIC_PRODUCTION_ZERO),
    ):
        values = thresholds.get(period)
        expected = set(minimums).union(maximums).union(zeros)
        if not isinstance(values, dict) or set(values) != expected:
            fail()
        minimum_bounds, maximum_bounds = bounds[period]
        checked: dict[str, float | int] = {}
        for field in minimums:
            value = finite_number(values.get(field))
            if value < minimum_bounds[field]:
                fail()
            checked[field] = value
        for field in maximums:
            value = finite_number(values.get(field))
            if field == "server5xxPercent":
                if value < 0 or value >= maximum_bounds[field]:
                    fail()
            elif value <= 0 or value > maximum_bounds[field]:
                fail()
            checked[field] = value
        for field in zeros:
            if type(values.get(field)) is not int or values[field] != 0:
                fail()
            checked[field] = 0
        result[period] = checked
    return result


def period_for_id(identifier: str) -> str:
    if identifier == BETA_ID:
        return "beta"
    if identifier in PRODUCTION_IDS:
        return "production"
    fail()


def expected_metric_fields(period: str) -> set[str]:
    if period == "beta":
        return set(STATIC_BETA_MINIMUMS).union(STATIC_BETA_MAXIMUMS) - {"minimumWindowHours"}
    return set(STATIC_PRODUCTION_MINIMUMS).union(STATIC_PRODUCTION_MAXIMUMS) - {"minimumWindowHours"}


def validate_source_document(
    document: dict[str, Any],
    identifier: str,
    threshold: dict[str, dict[str, float | int]],
) -> tuple[str, str, float, str, str]:
    period = period_for_id(identifier)
    expected_fields = {
        "schemaVersion", "artifactType", "id", "tag", "commit", "collectedAt", "source", "window", "denominators",
        "exclusions", "findings", "metrics", "zeroTolerance",
    }
    if set(document) != expected_fields or (
        document.get("schemaVersion") != 1
        or document.get("artifactType") != "runtime-floor-source"
        or document.get("id") != identifier
        or not isinstance(document.get("tag"), str)
        or TAG_RE.fullmatch(document["tag"]) is None
        or not isinstance(document.get("commit"), str)
        or COMMIT_RE.fullmatch(document["commit"]) is None
    ):
        fail()
    collected_at = parse_timestamp(document.get("collectedAt"))
    now = datetime.now(timezone.utc)
    if collected_at > now + timedelta(minutes=5) or now - collected_at > timedelta(hours=1):
        fail()
    source = document.get("source")
    if not isinstance(source, dict) or set(source) != {"providers", "querySHA256", "queryStartedAt", "queryEndedAt"}:
        fail()
    providers = source.get("providers")
    if not isinstance(providers, list) or not providers or any(not isinstance(item, str) or item not in ALLOWED_PROVIDERS for item in providers):
        fail()
    if len(set(providers)) != len(providers):
        fail()
    require_sha(source.get("querySHA256"))
    query_started = parse_timestamp(source.get("queryStartedAt"))
    query_ended = parse_timestamp(source.get("queryEndedAt"))
    if query_started > query_ended or query_ended > collected_at + timedelta(minutes=5) or now - query_ended > timedelta(hours=1):
        fail()
    window = document.get("window")
    if not isinstance(window, dict) or set(window) != {"startedAt", "endedAt", "durationHours"}:
        fail()
    window_started = parse_timestamp(window.get("startedAt"))
    window_ended = parse_timestamp(window.get("endedAt"))
    duration_hours = finite_number(window.get("durationHours"))
    actual_duration = (window_ended - window_started).total_seconds() / 3600
    if (
        window_started >= window_ended
        or abs(duration_hours - actual_duration) > 1 / 3600
        or window_ended > collected_at + timedelta(minutes=5)
        or query_ended < window_ended
    ):
        fail()
    required_window = float(threshold[period]["minimumWindowHours"])
    if duration_hours < required_window:
        fail()
    metric_fields = expected_metric_fields(period)
    denominators = document.get("denominators")
    if not isinstance(denominators, dict) or set(denominators) != metric_fields:
        fail()
    denominator_values = [positive_integer(denominators[field]) for field in metric_fields]
    exclusions = document.get("exclusions")
    if not isinstance(exclusions, dict) or set(exclusions) != EXCLUSION_FIELDS:
        fail()
    exclusion_total = sum(nonnegative_integer(exclusions[field]) for field in EXCLUSION_FIELDS)
    if exclusion_total >= min(denominator_values):
        fail()
    findings = document.get("findings")
    if not isinstance(findings, dict) or set(findings) != {"p0Count", "unresolvedP1Count"}:
        fail()
    if nonnegative_integer(findings["p0Count"]) != 0 or nonnegative_integer(findings["unresolvedP1Count"]) != 0:
        fail()
    metrics = document.get("metrics")
    if not isinstance(metrics, dict) or set(metrics) != metric_fields:
        fail()
    for field in metric_fields:
        value = finite_number(metrics[field])
        if field.endswith("Percent") and (value < 0 or value > 100):
            fail()
        if field in threshold[period] and field not in STATIC_BETA_MAXIMUMS and field not in STATIC_PRODUCTION_MAXIMUMS:
            if value < float(threshold[period][field]):
                fail()
        elif field in threshold[period]:
            limit = float(threshold[period][field])
            if field == "server5xxPercent":
                if value >= limit:
                    fail()
            elif value > limit:
                fail()
    zero_fields = STATIC_BETA_ZERO - {"p0Count", "unresolvedP1Count"} if period == "beta" else STATIC_PRODUCTION_ZERO - {"p0Count", "unresolvedP1Count"}
    zero_tolerance = document.get("zeroTolerance")
    if not isinstance(zero_tolerance, dict) or set(zero_tolerance) != zero_fields:
        fail()
    for field in zero_fields:
        if nonnegative_integer(zero_tolerance[field]) != 0:
            fail()
    return document["tag"], document["commit"], duration_hours, window["startedAt"], window["endedAt"]


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
    except (FloorError, OSError):
        for name in reversed(published):
            unlink_name(directory, name)
        fail()
    finally:
        for name in temporary:
            unlink_name(directory, name)
        os.close(directory)


def run() -> None:
    values = parse_arguments(sys.argv[1:])
    for value in values.values():
        reject_sensitive_text(value)
    period_for_id(values["id"])
    if values["schema"] != SCHEMA_PATH or values["output"] != f"Evidence/runtime/{values['id']}.json":
        fail()
    relative_parts(values["source_manifest"])
    relative_parts(values["threshold"])
    relative_parts(values["schema"])
    relative_parts(values["output"])
    if not values["source_manifest"].startswith("Evidence/") or not values["source_manifest"].endswith(".json"):
        fail()
    if not values["threshold"].startswith("Evidence/runtime/") or not values["threshold"].endswith(".json"):
        fail()
    root = repository_root()
    schema_raw = read_regular(root, values["schema"])
    schema = parse_json(schema_raw)
    if not isinstance(schema, dict):
        fail()
    reject_sensitive_data(schema)
    bounds = validate_schema(schema)
    source, _source_raw, source_digest = canonical_document(root, values["source_manifest"])
    threshold_document, _threshold_raw, threshold_digest = canonical_document(root, values["threshold"])
    verify_sidecar(root, values["source_manifest"], source_digest)
    verify_sidecar(root, values["threshold"], threshold_digest)
    threshold = validate_threshold_document(threshold_document, bounds)
    tag, commit, duration_hours, window_started, window_ended = validate_source_document(source, values["id"], threshold)
    if threshold_document["tag"] != tag or threshold_document["commit"] != commit:
        fail()
    record = {
        "schemaVersion": 1,
        "artifactType": "runtime-floor-validation",
        "id": values["id"],
        "status": "passed",
        "tag": tag,
        "commit": commit,
        "sourceManifestSHA256": source_digest,
        "thresholdSHA256": threshold_digest,
        "schemaSHA256": sha256(canonical_bytes(schema)),
        "windowStartedAt": window_started,
        "windowEndedAt": window_ended,
        "windowHours": duration_hours,
        "validatedAt": datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    write_pair(root, values["output"], record)


def main() -> int:
    try:
        run()
        return 0
    except FloorError:
        print("runtime floor validation failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
