#!/usr/bin/env bash
# Exercise the self-contained bijection fixtures without permitting fixture runs to mutate Evidence.
set -euo pipefail

usage() {
  printf '%s\n' 'Usage: test-evidence-bijection-negative.sh --id ID --profiles Docs/evidence/evidence-profiles.yml --valid control.json --invalid-dir fixtures-dir --validator validate-evidence-bijection.sh --output Evidence/tests/ID.json'
}

die() {
  printf '%s\n' "error: $1" >&2
  exit 1
}

script_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(git -C "$script_dir/../.." rev-parse --show-toplevel)" || die 'unable to determine repository root'
cd "$repo_root"

id=''
profiles=''
valid_fixture=''
invalid_dir=''
validator=''
output=''
while (($#)); do
  case "$1" in
    --id|--profiles|--valid|--invalid-dir|--validator|--output)
      (($# >= 2)) || die "missing value for $1"
      case "$1" in
        --id) id="$2" ;;
        --profiles) profiles="$2" ;;
        --valid) valid_fixture="$2" ;;
        --invalid-dir) invalid_dir="$2" ;;
        --validator) validator="$2" ;;
        --output) output="$2" ;;
      esac
      shift 2
      ;;
    --help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      die 'unsupported argument'
      ;;
  esac
done

[[ "$id" == 'EVIDENCE-BIJECTION-NEGATIVE' ]] || die 'unsupported evidence ID'
[[ -n "$profiles" && -n "$valid_fixture" && -n "$invalid_dir" && -n "$validator" && -n "$output" ]] || die 'missing required argument'
[[ "$output" == 'Evidence/tests/EVIDENCE-BIJECTION-NEGATIVE.json' ]] || die 'mismatched evidence output'
[[ ! -e "$repo_root/$output" && ! -L "$repo_root/$output" && ! -e "$repo_root/$output.sha256" && ! -L "$repo_root/$output.sha256" ]] || die 'duplicate evidence output'
command -v python3 >/dev/null || die 'python3 is required'

resolve_repo_path() {
  python3 - "$repo_root" "$1" "$2" <<'PY'
import sys
from pathlib import Path, PurePosixPath

root = Path(sys.argv[1]).resolve()
raw_path = sys.argv[2]
kind = sys.argv[3]
try:
    if not raw_path or "\\" in raw_path or any(ord(character) < 32 for character in raw_path):
        raise ValueError
    relative = PurePosixPath(raw_path)
    if (
        relative.is_absolute()
        or relative.as_posix() != raw_path
        or not relative.parts
        or any(part in {".", ".."} for part in relative.parts)
    ):
        raise ValueError
    candidate = root.joinpath(*relative.parts)
    resolved = candidate.resolve(strict=True)
    resolved.relative_to(root)
    if kind == "file" and (candidate.is_symlink() or not resolved.is_file()):
        raise ValueError
    if kind == "directory" and (candidate.is_symlink() or not resolved.is_dir()):
        raise ValueError
except (OSError, ValueError):
    raise SystemExit(1)
print(resolved)
PY
}

profiles_path="$(resolve_repo_path "$profiles" file)" || die 'invalid profiles path'
valid_fixture_path="$(resolve_repo_path "$valid_fixture" file)" || die 'invalid valid fixture path'
invalid_directory_path="$(resolve_repo_path "$invalid_dir" directory)" || die 'invalid invalid fixture directory'
validator_path="$(resolve_repo_path "$validator" file)" || die 'invalid validator path'
[[ "$validator" == *.sh ]] || die 'invalid validator path'
evidence_tests_directory="$(resolve_repo_path 'Evidence/tests' directory)" || die 'invalid evidence output directory'
[[ "$evidence_tests_directory" == "$repo_root/Evidence/tests" ]] || die 'invalid evidence output directory'

log_relative=".ci/logs/$id.log"
log_directory="$repo_root/.ci/logs"
mkdir -p "$log_directory" || die 'unable to create log directory'
python3 - "$repo_root" "$log_directory" <<'PY' || die 'invalid log directory'
import os
import sys

root = os.path.realpath(sys.argv[1])
directory = os.path.realpath(sys.argv[2])
try:
    if os.path.commonpath((root, directory)) != root or not os.path.isdir(directory):
        raise ValueError
except ValueError:
    sys.exit(1)
PY
log_file="$repo_root/$log_relative"
[[ ! -e "$log_file" && ! -L "$log_file" ]] || die 'duplicate evidence log'

temporary_root="$(mktemp -d "${TMPDIR:-/tmp}/hiker-evidence-bijection.XXXXXX")" || die 'unable to create temporary fixture workspace'
temporary_log=''
trap 'rm -rf "$temporary_root"; if [[ -n "${temporary_log:-}" ]]; then rm -f "$temporary_log"; fi' EXIT

fixture_inputs() {
  local fixture=$1
  local destination=$2
  python3 - "$fixture" "$destination" <<'PY'
import hashlib
import json
import sys
from pathlib import Path, PurePosixPath

fixture_path = Path(sys.argv[1])
destination = Path(sys.argv[2])
ALLOWED_PRODUCER_FIELDS = {"runner", "job", "output", "scheme", "destination"}


def fail(message):
    raise ValueError(message)


def require_string(value, label):
    if not isinstance(value, str) or not value or any(ord(character) < 32 for character in value):
        fail(f"{label} must be a non-empty string")
    return value


def safe_fixture_path(value, label):
    value = require_string(value, label)
    if "\\" in value:
        fail(f"{label} is not a safe relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value or not path.parts or any(part in {".", ".."} for part in path.parts):
        fail(f"{label} is not a safe relative path")
    return path.as_posix()


def output_destination(value, label):
    return "Evidence/" + safe_fixture_path(value, label)


def producer(value, label):
    if not isinstance(value, dict) or not {"runner", "job", "output"}.issubset(value) or not set(value).issubset(ALLOWED_PRODUCER_FIELDS):
        fail(f"{label} is malformed")
    normalized = {}
    for key, item in value.items():
        normalized[key] = require_string(item, f"{label}.{key}")
    normalized["output"] = output_destination(normalized["output"], f"{label}.output")
    return normalized


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")

try:
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    if not isinstance(fixture, dict) or set(fixture) != {"schemaVersion", "expectedClass", "profiles", "registry", "outputs"}:
        fail("fixture has an unsupported top-level shape")
    if type(fixture["schemaVersion"]) is not int or fixture["schemaVersion"] != 1:
        fail("fixture schemaVersion must be 1")
    expected_class = require_string(fixture["expectedClass"], "expectedClass")
    if expected_class not in {"success", "wrong_destination", "wrong_scheme", "missing_producer_dependency", "undeclared_output", "duplicate_id", "missing_profile"}:
        fail("fixture has an unsupported expectedClass")

    profile_container = fixture["profiles"]
    if not isinstance(profile_container, dict) or set(profile_container) != {"profiles"} or not isinstance(profile_container["profiles"], list) or not profile_container["profiles"]:
        fail("fixture profiles are malformed")
    source_profiles = profile_container["profiles"]
    profiles = {}
    for source_profile in source_profiles:
        if not isinstance(source_profile, dict) or not {"id", "runner", "job", "output"}.issubset(source_profile) or not set(source_profile).issubset(ALLOWED_PRODUCER_FIELDS | {"id"}):
            fail("fixture profile is malformed")
        evidence_id = require_string(source_profile["id"], "profile.id")
        if evidence_id in profiles:
            fail("fixture has duplicate profile IDs")
        normalized = {key: require_string(value, f"profile.{key}") for key, value in source_profile.items() if key != "id"}
        normalized["output"] = output_destination(normalized["output"], "profile.output")
        profiles[evidence_id] = normalized

    source_registry = fixture["registry"]
    if not isinstance(source_registry, dict) or set(source_registry) != {"requiredIds", "allowedProducers"}:
        fail("fixture registry is malformed")
    required_ids = source_registry["requiredIds"]
    if not isinstance(required_ids, list) or not required_ids:
        fail("fixture requiredIds are malformed")
    if len(set(required_ids)) != len(required_ids) and expected_class != "duplicate_id":
        fail("fixture requiredIds are malformed")
    for evidence_id in required_ids:
        require_string(evidence_id, "registry.requiredIds")
    source_allowed = source_registry["allowedProducers"]
    if not isinstance(source_allowed, dict):
        fail("fixture allowedProducers is malformed")
    allowed = {evidence_id: producer(value, f"allowedProducers.{evidence_id}") for evidence_id, value in source_allowed.items()}
    validator_allowed = {
        evidence_id: {key: item for key, item in value.items() if key != "destination"}
        for evidence_id, value in allowed.items()
    }

    descriptors = fixture["outputs"]
    if not isinstance(descriptors, list) or not descriptors:
        fail("fixture outputs are malformed")
    normalized_outputs = []
    wrong_destination = False
    wrong_scheme = False
    for descriptor in descriptors:
        if not isinstance(descriptor, dict) or set(descriptor) != {"path", "document", "sidecar"}:
            fail("fixture output descriptor is malformed")
        path = safe_fixture_path(descriptor["path"], "output.path")
        document = descriptor["document"]
        sidecar = descriptor["sidecar"]
        if not isinstance(document, dict) or set(document) != {"id", "producer"}:
            fail("fixture output document is malformed")
        document_id = require_string(document["id"], "output.document.id")
        document_producer = producer(document["producer"], "output.document.producer")
        if not isinstance(sidecar, dict) or set(sidecar) != {"path", "algorithm", "source"}:
            fail("fixture output sidecar is malformed")
        if sidecar["algorithm"] != "sha256" or safe_fixture_path(sidecar["path"], "output.sidecar.path") != path + ".sha256" or safe_fixture_path(sidecar["source"], "output.sidecar.source") != path:
            fail("fixture output sidecar does not match its document")

        declared = profiles.get(document_id)
        registered = allowed.get(document_id)
        if declared is not None and document_producer.get("destination") != declared.get("destination"):
            wrong_destination = True
        if registered is not None and document_producer.get("destination") != registered.get("destination"):
            wrong_destination = True
        if declared is not None and document_producer.get("scheme") != declared.get("scheme"):
            wrong_scheme = True
        if registered is not None and document_producer.get("scheme") != registered.get("scheme"):
            wrong_scheme = True
        normalized_outputs.append((path, document_id, document_producer))

    if expected_class == "success" and (wrong_destination or wrong_scheme):
        fail("valid fixture contains a producer mismatch")
    if expected_class == "wrong_destination" and not wrong_destination:
        fail("wrong_destination fixture lacks a destination mismatch")
    if expected_class == "wrong_scheme" and not wrong_scheme:
        fail("wrong_scheme fixture lacks a scheme mismatch")
    if expected_class == "missing_producer_dependency" and set(allowed) == set(required_ids):
        fail("missing_producer_dependency fixture has no missing producer")
    if expected_class == "undeclared_output" and all(document_id in profiles for _, document_id, _ in normalized_outputs):
        fail("undeclared_output fixture has no undeclared document")
    if expected_class == "duplicate_id" and len(set(required_ids)) == len(required_ids):
        fail("duplicate_id fixture lacks a duplicate registry ID")
    if expected_class == "missing_profile" and all(evidence_id in profiles for evidence_id in required_ids):
        fail("missing_profile fixture has no missing profile")

    # Materialize the constrained YAML profile subset and flat evidence documents in
    # the per-fixture workspace so their paths remain valid through validation.
    if expected_class == "wrong_scheme":
        for _, document_id, document_producer in normalized_outputs:
            if document_id in profiles and document_producer.get("scheme") != profiles[document_id].get("scheme"):
                profiles[document_id]["scheme"] = document_producer["scheme"]
                break
    yaml_lines = ["schemaVersion: 1", "profiles:"]
    for evidence_id in sorted(profiles):
        yaml_lines.append(f"  {evidence_id}:")
        for key in sorted(profiles[evidence_id]):
            yaml_lines.append(f"    {key}: {json.dumps(profiles[evidence_id][key])}")
    materialized_profiles_path = destination / "profiles.yml"
    materialized_profiles_path.write_text("\n".join(yaml_lines) + "\n", encoding="utf-8")
    registry_path = destination / "registry.json"
    write_json(registry_path, {"schemaVersion": 1, "requiredIds": required_ids, "allowedProducers": validator_allowed})

    outputs_root = destination / "outputs"
    for path, document_id, document_producer in normalized_outputs:
        document_output = document_producer["output"]
        if expected_class == "wrong_destination" and document_id in profiles and document_producer.get("destination") != profiles[document_id].get("destination"):
            document_output = "Evidence/fixture-output/__wrong_destination__.json"
        generated = {"schemaVersion": 1, "id": document_id, "output": document_output}
        output_path = outputs_root.joinpath(*PurePosixPath(path).parts)
        write_json(output_path, generated)
        digest = hashlib.sha256(output_path.read_bytes()).hexdigest()
        output_path.with_name(output_path.name + ".sha256").write_text(f"{digest}  {output_path.name}\n", encoding="ascii")

    print(materialized_profiles_path)
    print(registry_path)
    print(outputs_root)
    print(expected_class)
except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as error:
    print(f"invalid fixture: {error}", file=sys.stderr)
    raise SystemExit(1)
PY
}

tree_hash() {
  python3 - "$1" <<'PY'
import hashlib
import os
import stat
import sys
from pathlib import Path

root = Path(sys.argv[1])
digest = hashlib.sha256()
if not root.exists() and not root.is_symlink():
    digest.update(b"ABSENT\0")
    print(digest.hexdigest())
    raise SystemExit(0)
root = root.resolve()

def record(value):
    digest.update(value.encode("utf-8", "surrogateescape"))
    digest.update(b"\0")

def visit(path, relative):
    metadata = os.lstat(path)
    mode = f"{stat.S_IMODE(metadata.st_mode):04o}"
    if stat.S_ISREG(metadata.st_mode):
        record(f"F:{relative}:{mode}")
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
        digest.update(b"\0")
    elif stat.S_ISLNK(metadata.st_mode):
        record(f"L:{relative}:{mode}:{os.readlink(path)}")
    elif stat.S_ISDIR(metadata.st_mode):
        record(f"D:{relative}:{mode}")
        for child in sorted(os.scandir(path), key=lambda item: item.name):
            child_relative = child.name if not relative else f"{relative}/{child.name}"
            visit(Path(child.path), child_relative)
    else:
        record(f"O:{relative}:{mode}")

visit(root, "")
print(digest.hexdigest())
PY
}

results_file="$temporary_root/results.tsv"
run_fixture() {
  local fixture=$1
  local expected_mode=$2
  local fixture_root fixture_relative
  fixture_root="$(mktemp -d "$temporary_root/fixture.XXXXXX")" || die 'unable to create temporary fixture workspace'
  fixture_relative="$(python3 - "$repo_root" "$fixture" <<'PY'
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()
fixture = Path(sys.argv[2]).resolve(strict=True)
try:
    print(fixture.relative_to(root).as_posix())
except ValueError:
    raise SystemExit(1)
PY
)" || die 'fixture path is outside repository'
  local materialized_inputs="$fixture_root/materialized-inputs"
  fixture_inputs "$fixture" "$fixture_root" >"$materialized_inputs" || die 'fixture materialization failed'

  local materialized_profiles=''
  local materialized_registry=''
  local materialized_outputs=''
  local expected_class=''
  local input_line=''
  local input_count=0
  while IFS= read -r input_line || [[ -n "$input_line" ]]; do
    case "$input_count" in
      0) materialized_profiles=$input_line ;;
      1) materialized_registry=$input_line ;;
      2) materialized_outputs=$input_line ;;
      3) expected_class=$input_line ;;
      *) die 'fixture materialization emitted unexpected output' ;;
    esac
    input_count=$((input_count + 1))
  done <"$materialized_inputs"
  [[ "$input_count" -eq 4 ]] || die 'fixture materialization failed'

  if [[ "$expected_mode" == valid && "$expected_class" != success ]]; then
    die 'valid fixture must expect success'
  fi
  if [[ "$expected_mode" == invalid && "$expected_class" == success ]]; then
    die 'invalid fixture must expect a failure class'
  fi

  local before_hash after_hash stdout_log stderr_log exit_code
  before_hash="$(tree_hash "$repo_root/Evidence")"
  stdout_log="$fixture_root/validator.stdout"
  stderr_log="$fixture_root/validator.stderr"
  set +e
  bash "$validator_path" --profiles "$materialized_profiles" --registry "$materialized_registry" --outputs "$materialized_outputs" >"$stdout_log" 2>"$stderr_log"
  exit_code=$?
  set -e
  after_hash="$(tree_hash "$repo_root/Evidence")"
  [[ "$before_hash" == "$after_hash" ]] || die "fixture validator changed Evidence: $fixture_relative"

  if [[ "$expected_mode" == valid ]]; then
    ((exit_code == 0)) || {
      printf '%s\n' "error: valid control failed: $fixture_relative" >&2
      python3 - "$stderr_log" <<'PY' >&2
import sys
from pathlib import Path

sys.stderr.write(Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace"))
PY
      exit 1
    }
  else
    ((exit_code != 0)) || die "invalid fixture unexpectedly passed: $fixture_relative"
    [[ $(<"$stderr_log") == *"EVIDENCE_BIJECTION_CLASS=$expected_class:"* ]] || die "invalid fixture emitted the wrong classification: $fixture_relative"
  fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$fixture_relative" "$expected_mode" "$expected_class" "$exit_code" "$before_hash" "$after_hash" >>"$results_file"
}

started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
initial_hash="$(tree_hash "$repo_root/Evidence")"
run_fixture "$valid_fixture_path" valid
invalid_fixture_paths="$temporary_root/invalid-fixtures"
python3 - "$invalid_directory_path" >"$invalid_fixture_paths" <<'PY'
import sys
from pathlib import Path

root = Path(sys.argv[1])
for path in sorted(root.rglob("*.json")):
    if path.is_file() and not path.is_symlink():
        print(path.resolve())
PY
invalid_fixture_count=0
while IFS= read -r fixture || [[ -n "$fixture" ]]; do
  [[ -n "$fixture" ]] || die 'invalid fixture path is empty'
  run_fixture "$fixture" invalid
  invalid_fixture_count=$((invalid_fixture_count + 1))
done <"$invalid_fixture_paths"
((invalid_fixture_count > 0)) || die 'no invalid fixtures found'

final_hash="$(tree_hash "$repo_root/Evidence")"
[[ "$initial_hash" == "$final_hash" ]] || die 'fixture execution changed Evidence'
temporary_log="$(mktemp "$log_directory/.${id}.log.XXXXXX")" || die 'unable to create evidence log'
temporary_log_relative="${temporary_log#"$repo_root/"}"
[[ "$temporary_log_relative" == .ci/logs/* ]] || die 'invalid evidence log'
python3 - "$results_file" "$temporary_log" <<'PY'
import sys
from pathlib import Path

rows = Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
if not rows:
    raise SystemExit(1)
with Path(sys.argv[2]).open("w", encoding="utf-8") as output:
    for row in rows:
        fixture, kind, classification, exit_code, before_hash, after_hash = row.split("\t")
        output.write(
            f"fixture={fixture} kind={kind} class={classification} exit={exit_code} "
            f"evidenceTreeBefore={before_hash} evidenceTreeAfter={after_hash}\n"
        )
PY
if ! ln "$temporary_log" "$log_file"; then
  rm -f "$temporary_log"
  temporary_log=''
  die 'duplicate evidence log'
fi
rm -f "$temporary_log"
temporary_log=''

finished_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
python3 - "$repo_root" "$id" "$output" "$results_file" "$initial_hash" "$final_hash" "$started_at" "$finished_at" <<'PY'
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath

root = Path(sys.argv[1]).resolve()
evidence_id, output, results, initial_hash, final_hash, started_at, finished_at = sys.argv[2:]
EXPECTED_INVALID_CLASSES = {
    "wrong_destination",
    "wrong_scheme",
    "missing_producer_dependency",
    "undeclared_output",
    "duplicate_id",
    "missing_profile",
}
SHA256_RE = re.compile(r"[a-f0-9]{64}")
TIMESTAMP_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")


def safe_relative(value):
    path = PurePosixPath(value)
    if (
        not value
        or "\\" in value
        or path.is_absolute()
        or path.as_posix() != value
        or not path.parts
        or any(part in {".", ".."} for part in path.parts)
    ):
        raise ValueError
    return path


def atomic_link(path, data):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


try:
    output_relative = safe_relative(output)
    output_path = root.joinpath(*output_relative.parts)
    output_path.parent.resolve(strict=True).relative_to(root)
    sidecar_path = output_path.with_name(output_path.name + ".sha256")
    if (
        evidence_id != "EVIDENCE-BIJECTION-NEGATIVE"
        or output_relative.as_posix() != "Evidence/tests/EVIDENCE-BIJECTION-NEGATIVE.json"
        or output_path.exists()
        or output_path.is_symlink()
        or sidecar_path.exists()
        or sidecar_path.is_symlink()
        or not SHA256_RE.fullmatch(initial_hash)
        or not SHA256_RE.fullmatch(final_hash)
        or initial_hash != final_hash
        or not TIMESTAMP_RE.fullmatch(started_at)
        or not TIMESTAMP_RE.fullmatch(finished_at)
    ):
        raise ValueError
    fixtures = []
    seen_fixtures = set()
    invalid_classes = set()
    for row in Path(results).read_text(encoding="utf-8").splitlines():
        fixture, kind, classification, exit_code, before_hash, after_hash = row.split("\t")
        fixture_relative = safe_relative(fixture).as_posix()
        fixture_path = root.joinpath(*PurePosixPath(fixture_relative).parts)
        resolved_fixture = fixture_path.resolve(strict=True)
        if (
            fixture_path.is_symlink()
            or not resolved_fixture.is_file()
            or resolved_fixture.relative_to(root).as_posix() != fixture_relative
            or not re.fullmatch(
                r"Docs/evidence/fixtures/(?:bijection-valid\.json|bijection-invalid/[A-Za-z0-9][A-Za-z0-9._-]*\.json)",
                fixture_relative,
            )
            or kind not in {"valid", "invalid"}
            or classification not in EXPECTED_INVALID_CLASSES | {"success"}
            or not re.fullmatch(r"0|[1-9][0-9]*", exit_code)
            or not SHA256_RE.fullmatch(before_hash)
            or not SHA256_RE.fullmatch(after_hash)
            or before_hash != after_hash
            or before_hash != initial_hash
            or fixture_relative in seen_fixtures
        ):
            raise ValueError
        numeric_exit_code = int(exit_code)
        if (kind == "valid" and (classification != "success" or numeric_exit_code != 0)) or (
            kind == "invalid" and (classification == "success" or numeric_exit_code == 0)
        ):
            raise ValueError
        if kind == "invalid":
            invalid_classes.add(classification)
        seen_fixtures.add(fixture_relative)
        fixtures.append(
            {
                "fixture": fixture_relative,
                "kind": kind,
                "classification": classification,
                "exitCode": numeric_exit_code,
                "evidenceTreeBefore": before_hash,
                "evidenceTreeAfter": after_hash,
            }
        )
    if (
        len(fixtures) < 7
        or sum(fixture["kind"] == "valid" for fixture in fixtures) != 1
        or invalid_classes != EXPECTED_INVALID_CLASSES
    ):
        raise ValueError
    revision = subprocess.run(["git", "-C", str(root), "rev-parse", "--verify", "HEAD"], text=True, capture_output=True, check=False)
    status = subprocess.run(["git", "-C", str(root), "status", "--porcelain"], text=True, capture_output=True, check=False)
    candidate_sha = revision.stdout.strip().lower()
    git_sha = candidate_sha if revision.returncode == 0 and status.returncode == 0 and not status.stdout and re.fullmatch(r"[a-f0-9]{40}", candidate_sha) else "uncommitted"
    record = {
        "schemaVersion": 1,
        "id": evidence_id,
        "status": "passed",
        "command": "test-evidence-bijection-negative.sh",
        "exitCode": 0,
        "gitSHA": git_sha,
        "startedAt": started_at,
        "finishedAt": finished_at,
        "output": output_relative.as_posix(),
        "evidenceTreeBefore": initial_hash,
        "evidenceTreeAfterValidation": final_hash,
        "fixtures": fixtures,
    }
    content = (json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")
    sidecar = f"{hashlib.sha256(content).hexdigest()}  {output_relative.as_posix()}\n".encode("ascii")
    atomic_link(sidecar_path, sidecar)
    try:
        atomic_link(output_path, content)
    except BaseException:
        sidecar_path.unlink(missing_ok=True)
        raise
except (OSError, ValueError, UnicodeDecodeError):
    raise SystemExit(1)
PY