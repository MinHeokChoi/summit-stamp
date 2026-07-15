#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf '%s\n' 'Usage: run-xcode-evidence.sh --id ID --workspace PATH --scheme SCHEME --destination DESTINATION --filter TEST_FILTER --result .ci/results/ID.xcresult --output Evidence/tests/ID.json'
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
destination=''
filter=''
result=''
output=''
while (($#)); do
  case "$1" in
    --id|--workspace|--scheme|--destination|--filter|--result|--output)
      (($# >= 2)) || die "missing value for $1"
      case "$1" in
        --id) id="$2" ;;
        --workspace) workspace="$2" ;;
        --scheme) scheme="$2" ;;
        --destination) destination="$2" ;;
        --filter) filter="$2" ;;
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
[[ -n "$workspace" && -n "$scheme" && -n "$destination" && -n "$filter" && -n "$result" && -n "$output" ]] || die 'missing required argument'
[[ "$output" == "Evidence/tests/$id.json" ]] || die 'mismatched evidence output'
[[ "$workspace" == *.xcworkspace ]] || die 'invalid workspace path'
[[ "$result" == .ci/results/*.xcresult ]] || die 'invalid result path'
[[ ! -e "$repo_root/$output" && ! -L "$repo_root/$output" ]] || die 'duplicate evidence output'
command -v xcodebuild >/dev/null || die 'xcodebuild is not available'

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
result_path="$(resolve_repo_path "$result" destination)" || die 'invalid result path'

validate_text() {
  python3 - "$1" "$2" <<'PY'
import re
import sys

value, label = sys.argv[1:]
if not value or any(ord(character) < 32 for character in value):
    sys.exit(1)
if label in {"scheme", "destination"} and ("/" in value or "\\" in value or "~" in value or "$" in value):
    sys.exit(1)
if label == "filter" and (
    value.startswith("/")
    or "\\" in value
    or "~" in value
    or "$" in value
    or re.search(r"/(?:Users|home)/", value, re.IGNORECASE)
):
    sys.exit(1)
PY
}
validate_text "$scheme" scheme || die 'invalid scheme'
validate_text "$destination" destination || die 'invalid destination'
validate_text "$filter" filter || die 'invalid test filter'

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

command=(xcodebuild test -workspace "$workspace_path" -scheme "$scheme" -destination "$destination" "-only-testing:$filter" -resultBundlePath "$result_path")
recorded_command=(xcodebuild test -workspace "$workspace" -scheme "$scheme" -destination "$destination" "-only-testing:$filter" -resultBundlePath "$result")
command_json="$(python3 - "${recorded_command[@]}" <<'PY'
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

((exit_code == 0)) || die 'xcode evidence command failed'
[[ -d "$result_path" && ! -L "$result_path" ]] || die 'missing xcode result bundle'

counts="$(python3 - "$log_file" <<'PY'
import re
import sys
import os

skipped = 0
warnings = 0
warning_lines = []
skip_re = re.compile(r"(?i)(?:#\s*skip\b|\bTest Case\b.*\bskipped\b|\btests?\s+skipped\b)")
warning_re = re.compile(r"(?i)\bwarning\s*:")
no_appintents_re = re.compile(
    r"(?i).*warning:\s*Metadata extraction skipped\. No AppIntents\.framework dependency found\.\s*(?:\(in target .+\))?\s*$"
)
with open(sys.argv[1], encoding="utf-8", errors="replace") as source:
    for line in source:
        if no_appintents_re.fullmatch(line.rstrip("\n")):
            continue
        if skip_re.search(line):
            skipped += 1
        if warning_re.search(line):
            warnings += 1
            if len(warning_lines) < 20:
                warning_lines.append(line.rstrip("\n").replace(os.getcwd(), "$REPO"))
for line in warning_lines:
    print(f"xcode warning: {line}", file=sys.stderr)
print(f"{skipped}\t{warnings}")
PY
)" || die 'unable to inspect evidence log'
IFS=$'\t' read -r skipped_tests warnings <<< "$counts"
[[ "$skipped_tests" =~ ^[0-9]+$ && "$warnings" =~ ^[0-9]+$ ]] || die 'invalid evidence log counts'

python3 "$script_dir/write-evidence.py" \
  --id "$id" \
  --status passed \
  --runner xcode \
  --command-json "$command_json" \
  --exit-code "$exit_code" \
  --started-at "$started_at" \
  --finished-at "$finished_at" \
  --log "$log_relative" \
  --output "$output" \
  --skipped-tests "$skipped_tests" \
  --warnings "$warnings"
