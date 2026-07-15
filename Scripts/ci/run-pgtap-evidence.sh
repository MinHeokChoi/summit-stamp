#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf '%s\n' 'Usage: run-pgtap-evidence.sh --id ID --file Backend/tests/SHARD/TEST.sql --shard SHARD --output Evidence/tests/ID.json'
}

die() {
  printf '%s\n' "error: $1" >&2
  exit 1
}

script_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(git -C "$script_dir/../.." rev-parse --show-toplevel)" || die 'unable to determine repository root'
cd "$repo_root"

id=''
test_file=''
shard=''
output=''
while (($#)); do
  case "$1" in
    --id)
      (($# >= 2)) || die 'missing value for --id'
      id="$2"
      shift 2
      ;;
    --file)
      (($# >= 2)) || die 'missing value for --file'
      test_file="$2"
      shift 2
      ;;
    --shard)
      (($# >= 2)) || die 'missing value for --shard'
      shard="$2"
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
[[ -n "$test_file" && -n "$shard" && -n "$output" ]] || die 'missing required argument'
[[ "$output" == "Evidence/tests/$id.json" ]] || die 'mismatched evidence output'
[[ ! -e "$repo_root/$output" && ! -L "$repo_root/$output" ]] || die 'duplicate evidence output'
command -v supabase >/dev/null || die 'supabase is not available'
command -v pg_prove >/dev/null || die 'pg_prove is not available'

resolve_pgtap_test() {
  python3 - "$repo_root" "$1" "$2" <<'PY'
from pathlib import Path, PurePosixPath
import sys

root = Path(sys.argv[1]).resolve()
raw_path = sys.argv[2]
shard = sys.argv[3]
allowed_shards = {'grants', 'auth', 'rpc', 'self_read', 'friend_codes', 'stream', 'privacy', 'migration', 'rls'}
try:
    if shard not in allowed_shards or not raw_path or "\\" in raw_path or any(ord(character) < 32 for character in raw_path):
        raise ValueError
    relative = PurePosixPath(raw_path)
    if relative.is_absolute() or relative.as_posix() != raw_path or any(part in ('.', '..') for part in relative.parts):
        raise ValueError
    if len(relative.parts) != 4 or relative.parts[:3] != ('Backend', 'tests', shard) or relative.suffix != '.sql':
        raise ValueError
    candidate = (root / Path(*relative.parts)).resolve(strict=True)
    candidate.relative_to(root)
    if not candidate.is_file():
        raise ValueError
except (OSError, ValueError):
    sys.exit(1)
print(candidate)
PY
}
test_path="$(resolve_pgtap_test "$test_file" "$shard")" || die 'invalid pgTAP test file or shard'
test_path_relative="${test_path#"$repo_root/"}"
[[ "$test_path_relative" == Backend/tests/"$shard"/*.sql ]] || die 'invalid canonical pgTAP path'

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
temporary_status="$(mktemp "${TMPDIR:-/tmp}/hiker-evidence-status.XXXXXX")" || {
  rm -f "$temporary_log"
  die 'unable to query local Supabase status'
}
temporary_log_relative="${temporary_log#"$repo_root/"}"
[[ "$temporary_log_relative" == .ci/logs/* ]] || die 'invalid evidence log'
trap 'if [[ -n "${temporary_log:-}" ]]; then rm -f "$temporary_log"; fi; if [[ -n "${temporary_status:-}" ]]; then rm -f "$temporary_status"; fi' EXIT

set +e
supabase status --output json >"$temporary_status"
status_exit_code=$?
set -e
((status_exit_code == 0)) || die 'local Supabase services are unavailable'

local_db_url="$(python3 - "$temporary_status" <<'PY'
import json
from urllib.parse import urlsplit
import sys

LOCAL_HOSTS = {'localhost', '127.0.0.1', '::1'}
DB_KEYS = ('DB_URL', 'DB URL', 'db_url', 'database_url', 'databaseUrl')
API_KEYS = ('API_URL', 'API URL', 'api_url', 'apiUrl')

try:
    with open(sys.argv[1], encoding='utf-8') as source:
        status = json.load(source)
    if not isinstance(status, dict):
        raise ValueError

    db_values = [status[key] for key in DB_KEYS if isinstance(status.get(key), str) and status[key]]
    api_values = [status[key] for key in API_KEYS if isinstance(status.get(key), str) and status[key]]
    if len(db_values) != 1 or len(api_values) != 1:
        raise ValueError

    db_url = db_values[0]
    api_url = api_values[0]
    if 'service_role' in db_url.lower() or 'service_role' in api_url.lower():
        raise ValueError
    parsed_db = urlsplit(db_url)
    parsed_api = urlsplit(api_url)
    if parsed_db.scheme not in {'postgres', 'postgresql'} or parsed_db.hostname not in LOCAL_HOSTS:
        raise ValueError
    if not parsed_db.username or not parsed_db.password or not parsed_db.path:
        raise ValueError
    if parsed_api.scheme not in {'http', 'https'} or parsed_api.hostname not in LOCAL_HOSTS:
        raise ValueError
except (OSError, ValueError, json.JSONDecodeError):
    sys.exit(1)

print(db_url)
PY
)" || die 'unable to resolve local Supabase database'
rm -f "$temporary_status"
temporary_status=''

export PGOPTIONS='-c search_path=extensions,public'
command=(pg_prove --verbose --dbname "$local_db_url" "$test_path_relative")
command_metadata=(pg_prove --verbose --dbname '<local-supabase-db-url>' "$test_file")
command_json="$(python3 - "${command_metadata[@]}" <<'PY'
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

((exit_code == 0)) || die 'pgTAP evidence command failed'

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
  --runner pgtap \
  --command-json "$command_json" \
  --exit-code "$exit_code" \
  --started-at "$started_at" \
  --finished-at "$finished_at" \
  --log "$log_relative" \
  --output "$output" \
  --skipped-tests "$skipped_tests" \
  --warnings "$warnings"
