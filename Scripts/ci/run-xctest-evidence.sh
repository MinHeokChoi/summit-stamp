#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf '%s\n' 'Usage: run-xctest-evidence.sh --id ID --workspace PATH --scheme SCHEME --manifest PATH --xctestrun PATH --filter TEST_FILTER --destination DESTINATION --result .ci/results/ID.xcresult --output Evidence/tests/ID.json'
}

die() {
  printf '%s\n' "error: $1" >&2
  exit 1
}

script_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(git -C "$script_dir/../.." rev-parse --show-toplevel)" || die 'unable to determine repository root'
cd "$repo_root"

id=''
workspace=''
scheme=''
manifest=''
xctestrun=''
filter=''
destination=''
result=''
output=''
while (($#)); do
  case "$1" in
    --id|--workspace|--scheme|--manifest|--xctestrun|--filter|--destination|--result|--output)
      (($# >= 2)) || die "missing value for $1"
      case "$1" in
        --id) id="$2" ;;
        --workspace) workspace="$2" ;;
        --scheme) scheme="$2" ;;
        --manifest) manifest="$2" ;;
        --xctestrun) xctestrun="$2" ;;
        --filter) filter="$2" ;;
        --destination) destination="$2" ;;
        --result) result="$2" ;;
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

[[ "$id" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || die 'invalid evidence ID'
[[ -n "$workspace" && -n "$scheme" && -n "$manifest" && -n "$xctestrun" && -n "$filter" && -n "$destination" && -n "$result" && -n "$output" ]] || die 'missing required argument'
[[ "$workspace" == *.xcworkspace ]] || die 'invalid workspace path'
[[ "$manifest" == *.json ]] || die 'invalid manifest path'
[[ "$xctestrun" == *.xctestrun ]] || die 'invalid xctestrun path'
[[ "$result" == .ci/results/*.xcresult ]] || die 'invalid result path'
[[ "$output" == "Evidence/tests/$id.json" ]] || die 'mismatched evidence output'
[[ ! -e "$repo_root/$output" && ! -L "$repo_root/$output" ]] || die 'duplicate evidence output'
command -v xcodebuild >/dev/null || die 'xcodebuild is not available'
command -v python3 >/dev/null || die 'python3 is not available'

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
    resolved = candidate.resolve(strict=kind != "destination")
    resolved.relative_to(root)
    if kind == "file" and not resolved.is_file():
        raise ValueError
    if kind == "directory" and (candidate.is_symlink() or not resolved.is_dir()):
        raise ValueError
    if kind == "destination":
        resolved.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        resolved.parent.resolve(strict=True).relative_to(root)
        if candidate.exists() or candidate.is_symlink():
            raise ValueError
except (OSError, ValueError):
    raise SystemExit(1)
print(resolved)
PY
}

workspace_path="$(resolve_repo_path "$workspace" directory)" || die 'invalid workspace path'
manifest_path="$(resolve_repo_path "$manifest" file)" || die 'invalid manifest path'
xctestrun_path="$(resolve_repo_path "$xctestrun" file)" || die 'invalid xctestrun path'
result_path="$(resolve_repo_path "$result" destination)" || die 'invalid result path'
derived_data_path="$(resolve_repo_path '.ci/xctest/DerivedData' directory)" || die 'missing xctest derived data'

validate_text() {
  python3 - "$1" <<'PY'
import sys
value = sys.argv[1]
if not value or any(ord(character) < 32 for character in value):
    sys.exit(1)
PY
}
validate_text "$scheme" || die 'invalid scheme'
validate_text "$destination" || die 'invalid destination'
validate_text "$filter" || die 'invalid test filter'

python3 "$script_dir/verify-xctest-manifest.py" \
  --manifest "$manifest_path" \
  --derived-data "$derived_data_path" \
  --source-root "$repo_root" || die 'xctest manifest verification failed'
python3 - "$manifest_path" "$derived_data_path" "$xctestrun_path" <<'PY' || die 'manifest does not describe the requested xctestrun'
import json
import sys
from pathlib import Path, PurePosixPath

manifest_path = Path(sys.argv[1])
derived_data = Path(sys.argv[2]).resolve()
requested = Path(sys.argv[3]).resolve()
try:
    document = json.loads(manifest_path.read_text(encoding="utf-8"))
    relative = document["inputs"]["xctestrun"]
    if not isinstance(relative, str) or "\\" in relative:
        raise ValueError
    path = PurePosixPath(relative)
    if path.is_absolute() or not path.parts or any(part in {".", ".."} for part in path.parts):
        raise ValueError
    expected = derived_data.joinpath(*path.parts).resolve(strict=True)
    expected.relative_to(derived_data)
    if expected != requested:
        raise ValueError
except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
    raise SystemExit(1)
PY

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

umask 077
temporary_log="$(mktemp "$log_directory/.${id}.log.XXXXXX")" || die 'unable to create evidence log'
temporary_log_relative="${temporary_log#"$repo_root/"}"
[[ "$temporary_log_relative" == .ci/logs/* ]] || die 'invalid evidence log'
trap 'if [[ -n "${temporary_log:-}" ]]; then rm -f "$temporary_log"; fi; if [[ -n "${xcresult_json:-}" ]]; then rm -f "$xcresult_json"; fi' EXIT

command=(xcodebuild test-without-building -xctestrun "$xctestrun_path" "-only-testing:$filter" -destination "$destination" -resultBundlePath "$result_path")
command_json="$(python3 - "${command[@]}" <<'PY'
import json
import sys
print(json.dumps(sys.argv[1:], separators=(",", ":")))
PY
)" || die 'unable to encode evidence command'

started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
set +e
"${command[@]}" >"$temporary_log" 2>&1
exit_code=$?
set -e
finished_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

if ! python3 "$script_dir/write-evidence.py" --validate-log "$temporary_log_relative"; then
  rm -f "$temporary_log"
  temporary_log=''
  die 'unsafe evidence log'
fi
if ! ln "$temporary_log" "$log_file"; then
  rm -f "$temporary_log"
  temporary_log=''
  die 'duplicate evidence log'
fi
rm -f "$temporary_log"
temporary_log=''

((exit_code == 0)) || die 'xctest evidence command failed'
[[ -d "$result_path" && ! -L "$result_path" ]] || die 'missing xctest result bundle'

counts="$(python3 - "$log_file" <<'PY'
import re
import sys

skipped = 0
warnings = 0
with open(sys.argv[1], encoding="utf-8", errors="replace") as source:
    for line in source:
        if re.search(r"(?i)(?:#\s*skip\b|\bskipped\b)", line):
            skipped += 1
        if re.search(r"(?i)\bwarning\s*:", line):
            warnings += 1
print(f"{skipped}\t{warnings}")
PY
)" || die 'unable to inspect evidence log'
IFS=$'\t' read -r skipped_tests warnings <<< "$counts"
[[ "$skipped_tests" =~ ^[0-9]+$ && "$warnings" =~ ^[0-9]+$ ]] || die 'invalid evidence log counts'
((skipped_tests == 0)) || die 'xctest run skipped tests'
((warnings == 0)) || die 'xctest run emitted warnings'

if xcrun --find xcresulttool >/dev/null 2>&1; then
  xcresult_json="$(mktemp "${TMPDIR:-/tmp}/hiker-xcresult.XXXXXX")" || die 'unable to inspect xctest result'
  if ! xcrun xcresulttool get test-results tests --path "$result_path" --format json >"$xcresult_json" 2>&1; then
    if ! xcrun xcresulttool get --path "$result_path" --format json >"$xcresult_json" 2>&1; then
      die 'unable to inspect xctest result'
    fi
  fi
  python3 - "$xcresult_json" "$filter" <<'PY' || die 'xctest result did not prove the requested test passed without skips'
import json
import re
import sys
from collections.abc import Mapping, Sequence

path = sys.argv[1]
requested = sys.argv[2].rsplit("/", 1)[-1]
requested = re.sub(r"\(\)$", "", requested)
try:
    document = json.loads(open(path, encoding="utf-8").read())
except (OSError, UnicodeDecodeError, json.JSONDecodeError):
    raise SystemExit(1)

strings = []
records = []
def visit(value):
    if isinstance(value, Mapping):
        records.append(value)
        for child in value.values():
            visit(child)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for child in value:
            visit(child)
    elif isinstance(value, str):
        strings.append(value)
visit(document)
if any("skip" in value.lower() for value in strings):
    raise SystemExit(1)

def record_strings(record):
    values = []
    for key in ("name", "identifier", "testIdentifier", "testName", "title"):
        value = record.get(key)
        if isinstance(value, str):
            values.append(value)
    return values

matched = [record for record in records if any(requested in value.replace("()", "") for value in record_strings(record))]
if not matched:
    raise SystemExit(1)
for record in matched:
    statuses = [
        value.lower()
        for key, value in record.items()
        if key in {"result", "status", "testStatus", "state"} and isinstance(value, str)
    ]
    if any("skip" in value for value in statuses):
        raise SystemExit(1)
PY
  rm -f "$xcresult_json"
  xcresult_json=''
fi

python3 - "$repo_root" "$id" "$output" "$log_relative" "$result" "$manifest" "$command_json" "$started_at" "$finished_at" <<'PY'
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath

root = Path(sys.argv[1]).resolve()
evidence_id, output, log, result, manifest, command_json, started_at, finished_at = sys.argv[2:]
try:
    command = json.loads(command_json)
    if not isinstance(command, list) or not command:
        raise ValueError
    output_path = root.joinpath(*PurePosixPath(output).parts)
    log_path = root.joinpath(*PurePosixPath(log).parts)
    manifest_path = root.joinpath(*PurePosixPath(manifest).parts)
    if output != f"Evidence/tests/{evidence_id}.json" or output_path.exists() or output_path.is_symlink():
        raise ValueError
    sidecar_path = output_path.with_name(output_path.name + ".sha256")
    if sidecar_path.exists() or sidecar_path.is_symlink() or not log_path.is_file() or not manifest_path.is_file():
        raise ValueError
    revision = subprocess.run(["git", "-C", str(root), "rev-parse", "--verify", "HEAD"], text=True, capture_output=True, check=False)
    status = subprocess.run(["git", "-C", str(root), "status", "--porcelain"], text=True, capture_output=True, check=False)
    git_sha = revision.stdout.strip().lower() if revision.returncode == 0 and status.returncode == 0 and not status.stdout else "uncommitted"
    record = {
        "schemaVersion": 1,
        "id": evidence_id,
        "status": "passed",
        "runner": "xctest",
        "command": command,
        "exitCode": 0,
        "gitSHA": git_sha,
        "logSHA": hashlib.sha256(log_path.read_bytes()).hexdigest(),
        "manifestSHA": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "result": {"path": result},
        "timestamps": {"startedAt": started_at, "finishedAt": finished_at},
        "output": {"path": output},
        "skippedTests": 0,
        "warnings": 0,
    }
    content = (json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")
    sidecar = f"{hashlib.sha256(content).hexdigest()}  {output}\n".encode("ascii")
except (OSError, ValueError, TypeError, json.JSONDecodeError):
    raise SystemExit(1)


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
    atomic_link(sidecar_path, sidecar)
    try:
        atomic_link(output_path, content)
    except BaseException:
        sidecar_path.unlink(missing_ok=True)
        raise
except (OSError, ValueError):
    raise SystemExit(1)
PY
