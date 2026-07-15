#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf '%s\n' 'Usage: run-swift-evidence.sh --id ID --package PATH --filter TEST_FILTER --output Evidence/tests/ID.json'
}

die() {
  printf '%s\n' "error: $1" >&2
  exit 1
}

script_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(git -C "$script_dir/../.." rev-parse --show-toplevel)" || die 'unable to determine repository root'
cd "$repo_root"

id=''
package=''
filter=''
output=''
while (($#)); do
  case "$1" in
    --id)
      (($# >= 2)) || die 'missing value for --id'
      id="$2"
      shift 2
      ;;
    --package)
      (($# >= 2)) || die 'missing value for --package'
      package="$2"
      shift 2
      ;;
    --filter)
      (($# >= 2)) || die 'missing value for --filter'
      filter="$2"
      shift 2
      ;;
    --output)
      (($# >= 2)) || die 'missing value for --output'
      output="$2"
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
[[ -n "$package" && -n "$filter" && -n "$output" ]] || die 'missing required argument'
[[ "$output" == "Evidence/tests/$id.json" ]] || die 'mismatched evidence output'
[[ ! -e "$repo_root/$output" && ! -L "$repo_root/$output" ]] || die 'duplicate evidence output'
command -v swift >/dev/null || die 'swift is not available'

resolve_repo_path() {
  python3 - "$repo_root" "$1" "$2" <<'PY'
import os
from pathlib import Path, PurePosixPath
import sys

root = Path(sys.argv[1]).resolve()
raw_path = sys.argv[2]
kind = sys.argv[3]
try:
    if not raw_path or "\\" in raw_path or any(ord(character) < 32 for character in raw_path):
        raise ValueError
    relative = PurePosixPath(raw_path)
    if relative.is_absolute() or relative.as_posix() != raw_path or not relative.parts or any(part in (".", "..") for part in relative.parts):
        raise ValueError
    candidate = (root / Path(*relative.parts)).resolve(strict=True)
    candidate.relative_to(root)
    if kind == "directory" and not candidate.is_dir():
        raise ValueError
    if kind == "file" and not candidate.is_file():
        raise ValueError
except (OSError, ValueError):
    sys.exit(1)
print(candidate)
PY
}

package_path="$(resolve_repo_path "$package" directory)" || die 'invalid package path'
[[ -f "$package_path/Package.swift" ]] || die 'package manifest is missing'

validate_text() {
  python3 - "$1" <<'PY'
import sys
value = sys.argv[1]
if not value or any(ord(character) < 32 for character in value):
    sys.exit(1)
PY
}
validate_text "$filter" || die 'invalid test filter'

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
trap 'if [[ -n "${temporary_log:-}" ]]; then rm -f "$temporary_log"; fi' EXIT

command=(swift test --package-path "$package" --filter "$filter")
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

((exit_code == 0)) || die 'swift evidence command failed'

counts="$(python3 - "$log_file" <<'PY'
import re
import sys

skipped = 0
warnings = 0
with open(sys.argv[1], encoding='utf-8', errors='replace') as source:
    for line in source:
        if re.search(r'(?i)(?:#\s*skip\b|\bskipped\b)', line):
            skipped += 1
        if re.search(r'(?i)\bwarning\s*:', line):
            warnings += 1
print(f'{skipped}\t{warnings}')
PY
)" || die 'unable to inspect evidence log'
IFS=$'\t' read -r skipped_tests warnings <<< "$counts"
[[ "$skipped_tests" =~ ^[0-9]+$ && "$warnings" =~ ^[0-9]+$ ]] || die 'invalid evidence log counts'

python3 "$script_dir/write-evidence.py" \
  --id "$id" \
  --status passed \
  --runner swift \
  --command-json "$command_json" \
  --exit-code "$exit_code" \
  --started-at "$started_at" \
  --finished-at "$finished_at" \
  --log "$log_relative" \
  --output "$output" \
  --skipped-tests "$skipped_tests" \
  --warnings "$warnings"
